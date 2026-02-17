package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	ctx := context.Background()

	event := &Event{
		Type:     EventTypeBootstrap,
		Outcome:  OutcomeSuccess,
		Provider: "aws-kms",
		Message:  "Test bootstrap event",
		Resource: &ResourceInfo{
			Kind:      "GenesisBootstrap",
			Name:      "test-bootstrap",
			Namespace: "genesis-system",
		},
	}

	logger.Log(ctx, event)

	output := buf.String()
	require.NotEmpty(t, output)

	// Parse the JSON output
	var parsed Event
	err := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed)
	require.NoError(t, err)

	assert.Equal(t, EventTypeBootstrap, parsed.Type)
	assert.Equal(t, OutcomeSuccess, parsed.Outcome)
	assert.Equal(t, "aws-kms", parsed.Provider)
	assert.Equal(t, "Test bootstrap event", parsed.Message)
	assert.NotZero(t, parsed.Timestamp)
	assert.NotNil(t, parsed.Resource)
	assert.Equal(t, "test-bootstrap", parsed.Resource.Name)
}

func TestJSONLoggerTimestamp(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	ctx := context.Background()

	// Event without timestamp
	event := &Event{
		Type:    EventTypeDecrypt,
		Outcome: OutcomeSuccess,
	}

	before := time.Now().UTC()
	logger.Log(ctx, event)
	after := time.Now().UTC()

	var parsed Event
	err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &parsed)
	require.NoError(t, err)

	assert.True(t, !parsed.Timestamp.Before(before))
	assert.True(t, !parsed.Timestamp.After(after))
}

func TestLogBootstrap(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	ctx := context.Background()

	resource := &ResourceInfo{
		Kind:      "GenesisBootstrap",
		Name:      "test",
		Namespace: "default",
	}

	logger.LogBootstrap(ctx, resource, "gcp-kms", OutcomeSuccess, "Bootstrap completed", nil)

	var parsed Event
	err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &parsed)
	require.NoError(t, err)

	assert.Equal(t, EventTypeBootstrap, parsed.Type)
	assert.Equal(t, OutcomeSuccess, parsed.Outcome)
	assert.Equal(t, "gcp-kms", parsed.Provider)
	assert.Equal(t, "Bootstrap completed", parsed.Message)
	assert.Empty(t, parsed.Error)
}

func TestLogBootstrapWithError(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	ctx := context.Background()

	resource := &ResourceInfo{
		Kind: "GenesisBootstrap",
		Name: "test",
	}

	testErr := errors.New("KMS decryption failed")
	logger.LogBootstrap(ctx, resource, "aws-kms", OutcomeFailure, "Bootstrap failed", testErr)

	var parsed Event
	err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &parsed)
	require.NoError(t, err)

	assert.Equal(t, OutcomeFailure, parsed.Outcome)
	assert.Equal(t, "KMS decryption failed", parsed.Error)
}

func TestLogSecretOperation(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	ctx := context.Background()

	resource := &ResourceInfo{
		Kind:      "Secret",
		Name:      "sops-age",
		Namespace: "flux-system",
	}

	logger.LogSecretOperation(ctx, EventTypeSecretCreated, resource, OutcomeSuccess, "Secret created successfully")

	var parsed Event
	err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &parsed)
	require.NoError(t, err)

	assert.Equal(t, EventTypeSecretCreated, parsed.Type)
	assert.Equal(t, OutcomeSuccess, parsed.Outcome)
	assert.Equal(t, "Secret created successfully", parsed.Message)
}

func TestLogRotation(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	ctx := context.Background()

	resource := &ResourceInfo{
		Kind:      "Secret",
		Name:      "database-credentials",
		Namespace: "app",
	}

	logger.LogRotation(ctx, resource, OutcomeSuccess, "v1", "v2", nil)

	var parsed Event
	err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &parsed)
	require.NoError(t, err)

	assert.Equal(t, EventTypeRotation, parsed.Type)
	assert.Equal(t, OutcomeSuccess, parsed.Outcome)
	assert.Contains(t, parsed.Message, "v1")
	assert.Contains(t, parsed.Message, "v2")
	assert.Equal(t, "v1", parsed.Metadata["oldVersion"])
	assert.Equal(t, "v2", parsed.Metadata["newVersion"])
}

func TestLogAttestation(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	ctx := context.Background()

	resource := &ResourceInfo{
		Kind:      "GenesisBootstrap",
		Name:      "cluster-bootstrap",
		Namespace: "genesis-system",
	}

	actor := &ActorInfo{
		Type:     "serviceaccount",
		Name:     "genesis-operator",
		Identity: "system:serviceaccount:genesis-system:genesis-operator",
		Provider: "aws-irsa",
	}

	logger.LogAttestation(ctx, resource, actor, OutcomeSuccess, "Identity verified", nil)

	var parsed Event
	err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &parsed)
	require.NoError(t, err)

	assert.Equal(t, EventTypeAttestation, parsed.Type)
	assert.Equal(t, OutcomeSuccess, parsed.Outcome)
	assert.NotNil(t, parsed.Actor)
	assert.Equal(t, "genesis-operator", parsed.Actor.Name)
	assert.Equal(t, "aws-irsa", parsed.Actor.Provider)
}

func TestLogAuthFailure(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	ctx := context.Background()

	resource := &ResourceInfo{
		Kind:      "GenesisBootstrap",
		Name:      "test",
		Namespace: "default",
	}

	actor := &ActorInfo{
		Type:     "unknown",
		Identity: "untrusted-identity",
	}

	logger.LogAuthFailure(ctx, resource, actor, "Identity not trusted")

	var parsed Event
	err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &parsed)
	require.NoError(t, err)

	assert.Equal(t, EventTypeAuthFailure, parsed.Type)
	assert.Equal(t, OutcomeDenied, parsed.Outcome)
	assert.Equal(t, "Identity not trusted", parsed.Message)
}

func TestNopLogger(t *testing.T) {
	logger := NewNopLogger()
	ctx := context.Background()

	// Should not panic
	logger.Log(ctx, &Event{})
	logger.LogBootstrap(ctx, nil, "", OutcomeSuccess, "", nil)
	logger.LogSecretOperation(ctx, EventTypeSecretCreated, nil, OutcomeSuccess, "")
	logger.LogRotation(ctx, nil, OutcomeSuccess, "", "", nil)
	logger.LogAttestation(ctx, nil, nil, OutcomeSuccess, "", nil)
	logger.LogAuthFailure(ctx, nil, nil, "")

	assert.NoError(t, logger.Close())
}

func TestMultiLogger(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	logger1 := NewJSONLogger(&buf1)
	logger2 := NewJSONLogger(&buf2)
	multi := NewMultiLogger(logger1, logger2)
	ctx := context.Background()

	event := &Event{
		Type:    EventTypeBootstrap,
		Outcome: OutcomeSuccess,
		Message: "Multi-logger test",
	}

	multi.Log(ctx, event)

	// Both buffers should have output
	assert.NotEmpty(t, buf1.String())
	assert.NotEmpty(t, buf2.String())
	assert.Equal(t, buf1.String(), buf2.String())

	assert.NoError(t, multi.Close())
}

func TestGlobalLogger(t *testing.T) {
	// Save original global logger
	original := GetGlobalLogger()
	defer SetGlobalLogger(original)

	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	SetGlobalLogger(logger)

	ctx := context.Background()
	Log(ctx, &Event{Type: EventTypeBootstrap, Outcome: OutcomeSuccess})

	assert.NotEmpty(t, buf.String())
}

func TestEventTypes(t *testing.T) {
	assert.Equal(t, EventType("bootstrap"), EventTypeBootstrap)
	assert.Equal(t, EventType("decrypt"), EventTypeDecrypt)
	assert.Equal(t, EventType("secret_created"), EventTypeSecretCreated)
	assert.Equal(t, EventType("secret_updated"), EventTypeSecretUpdated)
	assert.Equal(t, EventType("secret_deleted"), EventTypeSecretDeleted)
	assert.Equal(t, EventType("rotation"), EventTypeRotation)
	assert.Equal(t, EventType("attestation"), EventTypeAttestation)
	assert.Equal(t, EventType("auth_failure"), EventTypeAuthFailure)
	assert.Equal(t, EventType("policy_violation"), EventTypePolicyViolation)
	assert.Equal(t, EventType("config_change"), EventTypeConfigChange)
}

func TestOutcomes(t *testing.T) {
	assert.Equal(t, Outcome("success"), OutcomeSuccess)
	assert.Equal(t, Outcome("failure"), OutcomeFailure)
	assert.Equal(t, Outcome("denied"), OutcomeDenied)
}

func TestLoggerClose(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	ctx := context.Background()

	// Log before close
	logger.Log(ctx, &Event{Type: EventTypeBootstrap})
	assert.NotEmpty(t, buf.String())

	initialLen := buf.Len()

	// Close the logger
	require.NoError(t, logger.Close())

	// Log after close should not write
	logger.Log(ctx, &Event{Type: EventTypeDecrypt})
	assert.Equal(t, initialLen, buf.Len())
}

func TestNewJSONLoggerFromPath(t *testing.T) {
	t.Run("creates logger and writes to file", func(t *testing.T) {
		// Create a temporary file
		tmpFile, err := os.CreateTemp("", "audit-test-*.log")
		require.NoError(t, err)
		tmpPath := tmpFile.Name()
		tmpFile.Close()
		defer os.Remove(tmpPath)

		// Create logger from path
		logger, err := NewJSONLoggerFromPath(tmpPath)
		require.NoError(t, err)
		require.NotNil(t, logger)

		ctx := context.Background()
		event := &Event{
			Type:     EventTypeBootstrap,
			Outcome:  OutcomeSuccess,
			Provider: "aws-kms",
			Message:  "File-based audit log test",
			Resource: &ResourceInfo{
				Kind:      "GenesisBootstrap",
				Name:      "test-bootstrap",
				Namespace: "genesis-system",
			},
		}

		// Log an event
		logger.Log(ctx, event)

		// Close the logger to flush
		require.NoError(t, logger.Close())

		// Read the file and verify contents
		content, err := os.ReadFile(tmpPath)
		require.NoError(t, err)
		assert.NotEmpty(t, content)

		// Parse the JSON output
		var parsed Event
		err = json.Unmarshal(bytes.TrimSpace(content), &parsed)
		require.NoError(t, err)

		assert.Equal(t, EventTypeBootstrap, parsed.Type)
		assert.Equal(t, OutcomeSuccess, parsed.Outcome)
		assert.Equal(t, "aws-kms", parsed.Provider)
		assert.Equal(t, "File-based audit log test", parsed.Message)
		assert.NotNil(t, parsed.Resource)
		assert.Equal(t, "test-bootstrap", parsed.Resource.Name)
	})

	t.Run("appends to existing file", func(t *testing.T) {
		// Create a temporary file with existing content
		tmpFile, err := os.CreateTemp("", "audit-test-append-*.log")
		require.NoError(t, err)
		tmpPath := tmpFile.Name()
		tmpFile.Close()
		defer os.Remove(tmpPath)

		ctx := context.Background()

		// First logger writes first event
		logger1, err := NewJSONLoggerFromPath(tmpPath)
		require.NoError(t, err)
		logger1.Log(ctx, &Event{Type: EventTypeBootstrap, Outcome: OutcomeSuccess, Message: "First event"})
		require.NoError(t, logger1.Close())

		// Second logger appends second event
		logger2, err := NewJSONLoggerFromPath(tmpPath)
		require.NoError(t, err)
		logger2.Log(ctx, &Event{Type: EventTypeDecrypt, Outcome: OutcomeSuccess, Message: "Second event"})
		require.NoError(t, logger2.Close())

		// Read file and verify both events exist
		content, err := os.ReadFile(tmpPath)
		require.NoError(t, err)

		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		assert.Len(t, lines, 2, "Should have two log entries")

		var event1, event2 Event
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &event1))
		require.NoError(t, json.Unmarshal([]byte(lines[1]), &event2))

		assert.Equal(t, "First event", event1.Message)
		assert.Equal(t, "Second event", event2.Message)
	})

	t.Run("returns error for invalid path", func(t *testing.T) {
		// Try to create logger with invalid path (directory that doesn't exist)
		logger, err := NewJSONLoggerFromPath("/nonexistent/directory/audit.log")
		assert.Error(t, err)
		assert.Nil(t, logger)
		assert.Contains(t, err.Error(), "failed to open audit log file")
	})

	t.Run("creates file with correct permissions", func(t *testing.T) {
		// Create a temporary directory
		tmpDir, err := os.MkdirTemp("", "audit-test-perms-*")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		tmpPath := tmpDir + "/new-audit.log"

		// Create logger - should create the file
		logger, err := NewJSONLoggerFromPath(tmpPath)
		require.NoError(t, err)
		require.NotNil(t, logger)

		// Log something to ensure file is written
		logger.Log(context.Background(), &Event{Type: EventTypeBootstrap})
		require.NoError(t, logger.Close())

		// Verify file exists and has restrictive permissions (0600)
		info, err := os.Stat(tmpPath)
		require.NoError(t, err)
		// On Unix systems, verify the file has restrictive permissions
		// The file should be created with 0600 permissions
		perm := info.Mode().Perm()
		assert.Equal(t, os.FileMode(0600), perm, "Audit log should have 0600 permissions for security")
	})
}

// Test global logger convenience functions
func TestGlobalLoggerFunctions(t *testing.T) {
	// Save original global logger
	original := GetGlobalLogger()
	defer SetGlobalLogger(original)

	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	SetGlobalLogger(logger)

	ctx := context.Background()
	resource := &ResourceInfo{
		Kind:      "GenesisBootstrap",
		Name:      "test",
		Namespace: "default",
	}
	actor := &ActorInfo{
		Type:     "serviceaccount",
		Name:     "genesis-operator",
		Identity: "system:serviceaccount:default:genesis-operator",
	}

	t.Run("LogBootstrap global function", func(t *testing.T) {
		buf.Reset()
		LogBootstrap(ctx, resource, "aws-kms", OutcomeSuccess, "Global bootstrap test", nil)

		var parsed Event
		err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &parsed)
		require.NoError(t, err)
		assert.Equal(t, EventTypeBootstrap, parsed.Type)
		assert.Equal(t, "Global bootstrap test", parsed.Message)
	})

	t.Run("LogSecretOperation global function", func(t *testing.T) {
		buf.Reset()
		LogSecretOperation(ctx, EventTypeSecretCreated, resource, OutcomeSuccess, "Global secret test")

		var parsed Event
		err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &parsed)
		require.NoError(t, err)
		assert.Equal(t, EventTypeSecretCreated, parsed.Type)
		assert.Equal(t, "Global secret test", parsed.Message)
	})

	t.Run("LogRotation global function", func(t *testing.T) {
		buf.Reset()
		LogRotation(ctx, resource, OutcomeSuccess, "v1", "v2", nil)

		var parsed Event
		err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &parsed)
		require.NoError(t, err)
		assert.Equal(t, EventTypeRotation, parsed.Type)
		assert.Equal(t, "v1", parsed.Metadata["oldVersion"])
		assert.Equal(t, "v2", parsed.Metadata["newVersion"])
	})

	t.Run("LogAttestation global function", func(t *testing.T) {
		buf.Reset()
		LogAttestation(ctx, resource, actor, OutcomeSuccess, "Global attestation test", nil)

		var parsed Event
		err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &parsed)
		require.NoError(t, err)
		assert.Equal(t, EventTypeAttestation, parsed.Type)
		assert.Equal(t, "Global attestation test", parsed.Message)
	})

	t.Run("LogAuthFailure global function", func(t *testing.T) {
		buf.Reset()
		LogAuthFailure(ctx, resource, actor, "Global auth failure test")

		var parsed Event
		err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &parsed)
		require.NoError(t, err)
		assert.Equal(t, EventTypeAuthFailure, parsed.Type)
		assert.Equal(t, OutcomeDenied, parsed.Outcome)
		assert.Equal(t, "Global auth failure test", parsed.Message)
	})
}

// Test MultiLogger convenience methods
func TestMultiLoggerMethods(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	logger1 := NewJSONLogger(&buf1)
	logger2 := NewJSONLogger(&buf2)
	multi := NewMultiLogger(logger1, logger2)
	ctx := context.Background()

	resource := &ResourceInfo{
		Kind:      "GenesisBootstrap",
		Name:      "test",
		Namespace: "default",
	}
	actor := &ActorInfo{
		Type:     "serviceaccount",
		Name:     "genesis-operator",
		Identity: "system:serviceaccount:default:genesis-operator",
	}

	t.Run("LogBootstrap writes to all loggers", func(t *testing.T) {
		buf1.Reset()
		buf2.Reset()
		multi.LogBootstrap(ctx, resource, "gcp-kms", OutcomeSuccess, "Multi bootstrap", nil)

		assert.NotEmpty(t, buf1.String())
		assert.NotEmpty(t, buf2.String())

		var parsed1, parsed2 Event
		err := json.Unmarshal(bytes.TrimSpace(buf1.Bytes()), &parsed1)
		require.NoError(t, err)
		err = json.Unmarshal(bytes.TrimSpace(buf2.Bytes()), &parsed2)
		require.NoError(t, err)
		assert.Equal(t, EventTypeBootstrap, parsed1.Type)
		assert.Equal(t, parsed1.Type, parsed2.Type)
		assert.Equal(t, parsed1.Message, parsed2.Message)
	})

	t.Run("LogSecretOperation writes to all loggers", func(t *testing.T) {
		buf1.Reset()
		buf2.Reset()
		multi.LogSecretOperation(ctx, EventTypeSecretUpdated, resource, OutcomeSuccess, "Multi secret op")

		assert.NotEmpty(t, buf1.String())
		assert.NotEmpty(t, buf2.String())

		var parsed1, parsed2 Event
		err := json.Unmarshal(bytes.TrimSpace(buf1.Bytes()), &parsed1)
		require.NoError(t, err)
		err = json.Unmarshal(bytes.TrimSpace(buf2.Bytes()), &parsed2)
		require.NoError(t, err)
		assert.Equal(t, EventTypeSecretUpdated, parsed1.Type)
		assert.Equal(t, parsed1.Type, parsed2.Type)
		assert.Equal(t, parsed1.Message, parsed2.Message)
	})

	t.Run("LogRotation writes to all loggers", func(t *testing.T) {
		buf1.Reset()
		buf2.Reset()
		multi.LogRotation(ctx, resource, OutcomeSuccess, "v2", "v3", nil)

		assert.NotEmpty(t, buf1.String())
		assert.NotEmpty(t, buf2.String())

		var parsed1, parsed2 Event
		err := json.Unmarshal(bytes.TrimSpace(buf1.Bytes()), &parsed1)
		require.NoError(t, err)
		err = json.Unmarshal(bytes.TrimSpace(buf2.Bytes()), &parsed2)
		require.NoError(t, err)
		assert.Equal(t, EventTypeRotation, parsed1.Type)
		assert.Equal(t, parsed1.Type, parsed2.Type)
	})

	t.Run("LogAttestation writes to all loggers", func(t *testing.T) {
		buf1.Reset()
		buf2.Reset()
		multi.LogAttestation(ctx, resource, actor, OutcomeSuccess, "Multi attestation", nil)

		assert.NotEmpty(t, buf1.String())
		assert.NotEmpty(t, buf2.String())

		var parsed1, parsed2 Event
		err := json.Unmarshal(bytes.TrimSpace(buf1.Bytes()), &parsed1)
		require.NoError(t, err)
		err = json.Unmarshal(bytes.TrimSpace(buf2.Bytes()), &parsed2)
		require.NoError(t, err)
		assert.Equal(t, EventTypeAttestation, parsed1.Type)
		assert.Equal(t, parsed1.Type, parsed2.Type)
		assert.Equal(t, parsed1.Message, parsed2.Message)
	})

	t.Run("LogAuthFailure writes to all loggers", func(t *testing.T) {
		buf1.Reset()
		buf2.Reset()
		multi.LogAuthFailure(ctx, resource, actor, "Multi auth failure")

		assert.NotEmpty(t, buf1.String())
		assert.NotEmpty(t, buf2.String())

		var parsed1, parsed2 Event
		err := json.Unmarshal(bytes.TrimSpace(buf1.Bytes()), &parsed1)
		require.NoError(t, err)
		err = json.Unmarshal(bytes.TrimSpace(buf2.Bytes()), &parsed2)
		require.NoError(t, err)
		assert.Equal(t, EventTypeAuthFailure, parsed1.Type)
		assert.Equal(t, parsed1.Type, parsed2.Type)
		assert.Equal(t, parsed1.Message, parsed2.Message)
	})
}

// Test LogRotation with error
func TestLogRotationWithError(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	ctx := context.Background()

	resource := &ResourceInfo{
		Kind:      "Secret",
		Name:      "test-secret",
		Namespace: "default",
	}

	testErr := errors.New("rotation failed due to key expiry")
	logger.LogRotation(ctx, resource, OutcomeFailure, "v1", "v2", testErr)

	var parsed Event
	err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &parsed)
	require.NoError(t, err)

	assert.Equal(t, EventTypeRotation, parsed.Type)
	assert.Equal(t, OutcomeFailure, parsed.Outcome)
	assert.Equal(t, "rotation failed due to key expiry", parsed.Error)
}

// Test LogAttestation with error
func TestLogAttestationWithError(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	ctx := context.Background()

	resource := &ResourceInfo{
		Kind:      "GenesisBootstrap",
		Name:      "test",
		Namespace: "default",
	}
	actor := &ActorInfo{
		Type:     "unknown",
		Identity: "untrusted-identity",
	}

	testErr := errors.New("OIDC token validation failed")
	logger.LogAttestation(ctx, resource, actor, OutcomeFailure, "Attestation failed", testErr)

	var parsed Event
	err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &parsed)
	require.NoError(t, err)

	assert.Equal(t, EventTypeAttestation, parsed.Type)
	assert.Equal(t, OutcomeFailure, parsed.Outcome)
	assert.Equal(t, "OIDC token validation failed", parsed.Error)
}

// Test MultiLogger Close with error
func TestMultiLoggerCloseWithError(t *testing.T) {
	// Create a custom writer that returns error on close
	errWriter := &errorCloser{err: errors.New("close error")}
	logger1 := NewJSONLogger(errWriter)

	var buf bytes.Buffer
	logger2 := NewJSONLogger(&buf)

	multi := NewMultiLogger(logger1, logger2)

	err := multi.Close()
	assert.Error(t, err)
	assert.Equal(t, "close error", err.Error())
}

// errorCloser is a writer that returns an error on Close
type errorCloser struct {
	err error
}

func (e *errorCloser) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (e *errorCloser) Close() error {
	return e.err
}

// Test Event with pre-set timestamp
func TestEventWithPresetTimestamp(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	ctx := context.Background()

	presetTime := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	event := &Event{
		Type:      EventTypeBootstrap,
		Outcome:   OutcomeSuccess,
		Timestamp: presetTime,
		Message:   "Test with preset timestamp",
	}

	logger.Log(ctx, event)

	var parsed Event
	err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &parsed)
	require.NoError(t, err)

	// The preset timestamp should be preserved
	assert.Equal(t, presetTime.Year(), parsed.Timestamp.Year())
	assert.Equal(t, presetTime.Month(), parsed.Timestamp.Month())
	assert.Equal(t, presetTime.Day(), parsed.Timestamp.Day())
}

// Test Event with all fields populated
func TestEventFullFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	ctx := context.Background()

	event := &Event{
		Type:    EventTypeBootstrap,
		Outcome: OutcomeSuccess,
		Resource: &ResourceInfo{
			Kind:      "GenesisBootstrap",
			Name:      "test-bootstrap",
			Namespace: "genesis-system",
			UID:       "abc-123-def",
		},
		Actor: &ActorInfo{
			Type:      "serviceaccount",
			Name:      "genesis-operator",
			Namespace: "genesis-system",
			Identity:  "system:serviceaccount:genesis-system:genesis-operator",
			Provider:  "aws-irsa",
		},
		Provider:  "aws-kms",
		Message:   "Full event test",
		RequestID: "req-12345",
		Duration:  150 * time.Millisecond,
		Metadata: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}

	logger.Log(ctx, event)

	var parsed Event
	err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &parsed)
	require.NoError(t, err)

	assert.Equal(t, EventTypeBootstrap, parsed.Type)
	assert.Equal(t, OutcomeSuccess, parsed.Outcome)
	assert.Equal(t, "aws-kms", parsed.Provider)
	assert.Equal(t, "Full event test", parsed.Message)
	assert.Equal(t, "req-12345", parsed.RequestID)
	assert.Equal(t, 150*time.Millisecond, parsed.Duration)

	require.NotNil(t, parsed.Resource)
	assert.Equal(t, "abc-123-def", parsed.Resource.UID)

	require.NotNil(t, parsed.Actor)
	assert.Equal(t, "genesis-system", parsed.Actor.Namespace)

	assert.Equal(t, "value1", parsed.Metadata["key1"])
	assert.Equal(t, "value2", parsed.Metadata["key2"])
}

// Test NopLogger all convenience methods
func TestNopLoggerAllMethods(t *testing.T) {
	logger := NewNopLogger()
	ctx := context.Background()

	resource := &ResourceInfo{
		Kind:      "GenesisBootstrap",
		Name:      "test",
		Namespace: "default",
	}
	actor := &ActorInfo{
		Type:     "serviceaccount",
		Name:     "test-sa",
		Identity: "system:serviceaccount:default:test-sa",
	}

	// All these should be no-ops (not panic)
	logger.Log(ctx, &Event{Type: EventTypeBootstrap})
	logger.LogBootstrap(ctx, resource, "aws-kms", OutcomeSuccess, "test", nil)
	logger.LogSecretOperation(ctx, EventTypeSecretCreated, resource, OutcomeSuccess, "test")
	logger.LogRotation(ctx, resource, OutcomeSuccess, "v1", "v2", nil)
	logger.LogAttestation(ctx, resource, actor, OutcomeSuccess, "test", nil)
	logger.LogAuthFailure(ctx, resource, actor, "test reason")

	// Close should return nil
	err := logger.Close()
	assert.NoError(t, err)
}
