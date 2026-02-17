// Package audit provides structured audit logging for security-relevant events
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// EventType represents the type of audit event
type EventType string

const (
	// EventTypeBootstrap is logged when a bootstrap operation occurs
	EventTypeBootstrap EventType = "bootstrap"

	// EventTypeDecrypt is logged when decryption is performed
	EventTypeDecrypt EventType = "decrypt"

	// EventTypeSecretCreated is logged when a secret is created
	EventTypeSecretCreated EventType = "secret_created"

	// EventTypeSecretUpdated is logged when a secret is updated
	EventTypeSecretUpdated EventType = "secret_updated"

	// EventTypeSecretDeleted is logged when a secret is deleted
	EventTypeSecretDeleted EventType = "secret_deleted"

	// EventTypeRotation is logged when key rotation occurs
	EventTypeRotation EventType = "rotation"

	// EventTypeAttestation is logged when identity attestation is performed
	EventTypeAttestation EventType = "attestation"

	// EventTypeAuthFailure is logged when authentication fails
	EventTypeAuthFailure EventType = "auth_failure"

	// EventTypePolicyViolation is logged when a policy violation is detected
	EventTypePolicyViolation EventType = "policy_violation"

	// EventTypeConfigChange is logged when configuration changes
	EventTypeConfigChange EventType = "config_change"
)

// Outcome represents the result of an operation
type Outcome string

const (
	// OutcomeSuccess indicates a successful operation
	OutcomeSuccess Outcome = "success"

	// OutcomeFailure indicates a failed operation
	OutcomeFailure Outcome = "failure"

	// OutcomeDenied indicates an operation was denied
	OutcomeDenied Outcome = "denied"
)

// Event represents an audit event
type Event struct {
	// Timestamp is when the event occurred
	Timestamp time.Time `json:"timestamp"`

	// Type is the type of event
	Type EventType `json:"type"`

	// Outcome is the result of the operation
	Outcome Outcome `json:"outcome"`

	// Resource contains information about the affected resource
	Resource *ResourceInfo `json:"resource,omitempty"`

	// Actor contains information about who performed the action
	Actor *ActorInfo `json:"actor,omitempty"`

	// Provider is the KMS provider used (if applicable)
	Provider string `json:"provider,omitempty"`

	// Message provides human-readable details
	Message string `json:"message,omitempty"`

	// Error contains error details if the operation failed
	Error string `json:"error,omitempty"`

	// Metadata contains additional key-value data
	Metadata map[string]string `json:"metadata,omitempty"`

	// RequestID is a unique identifier for the request
	RequestID string `json:"requestId,omitempty"`

	// Duration is how long the operation took
	Duration time.Duration `json:"duration,omitempty"`
}

// ResourceInfo contains information about a resource
type ResourceInfo struct {
	// Kind is the Kubernetes resource kind
	Kind string `json:"kind,omitempty"`

	// Name is the resource name
	Name string `json:"name,omitempty"`

	// Namespace is the resource namespace
	Namespace string `json:"namespace,omitempty"`

	// UID is the resource UID
	UID string `json:"uid,omitempty"`
}

// ActorInfo contains information about the actor
type ActorInfo struct {
	// Type is the type of actor (user, serviceaccount, system)
	Type string `json:"type,omitempty"`

	// Name is the actor's name
	Name string `json:"name,omitempty"`

	// Namespace is the actor's namespace (for service accounts)
	Namespace string `json:"namespace,omitempty"`

	// Identity is the full identity string
	Identity string `json:"identity,omitempty"`

	// Provider is the identity provider (aws-irsa, gcp-wi, github-actions, etc.)
	Provider string `json:"provider,omitempty"`
}

// Logger is the audit logger interface
type Logger interface {
	// Log logs an audit event
	Log(ctx context.Context, event *Event)

	// LogBootstrap logs a bootstrap event
	LogBootstrap(ctx context.Context, resource *ResourceInfo, provider string, outcome Outcome, message string, err error)

	// LogSecretOperation logs a secret operation
	LogSecretOperation(ctx context.Context, eventType EventType, resource *ResourceInfo, outcome Outcome, message string)

	// LogRotation logs a rotation event
	LogRotation(ctx context.Context, resource *ResourceInfo, outcome Outcome, oldVersion, newVersion string, err error)

	// LogAttestation logs an attestation event
	LogAttestation(ctx context.Context, resource *ResourceInfo, actor *ActorInfo, outcome Outcome, message string, err error)

	// LogAuthFailure logs an authentication failure
	LogAuthFailure(ctx context.Context, resource *ResourceInfo, actor *ActorInfo, reason string)

	// Close closes the logger
	Close() error
}

// JSONLogger logs audit events in JSON format
type JSONLogger struct {
	mu     sync.Mutex
	writer io.Writer
	closed bool
}

// NewJSONLogger creates a new JSON audit logger
func NewJSONLogger(writer io.Writer) *JSONLogger {
	return &JSONLogger{
		writer: writer,
	}
}

// NewJSONLoggerFromPath creates a JSON logger that writes to a file
func NewJSONLoggerFromPath(path string) (*JSONLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600) // #nosec G304 -- path is from operator configuration
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}
	return NewJSONLogger(f), nil
}

// Log logs an audit event
func (l *JSONLogger) Log(ctx context.Context, event *Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(event)
	if err != nil {
		logger := log.FromContext(ctx)
		logger.Error(err, "Failed to marshal audit event")
		return
	}

	// Write JSON line - errors are logged but not propagated as audit logging
	// should not interrupt the main operation flow
	if _, err := l.writer.Write(data); err != nil {
		logger := log.FromContext(ctx)
		logger.Error(err, "Failed to write audit event")
		return
	}
	if _, err := l.writer.Write([]byte("\n")); err != nil {
		logger := log.FromContext(ctx)
		logger.Error(err, "Failed to write audit event newline")
	}
}

// LogBootstrap logs a bootstrap event
func (l *JSONLogger) LogBootstrap(ctx context.Context, resource *ResourceInfo, provider string, outcome Outcome, message string, err error) {
	event := &Event{
		Type:     EventTypeBootstrap,
		Outcome:  outcome,
		Resource: resource,
		Provider: provider,
		Message:  message,
	}
	if err != nil {
		event.Error = err.Error()
	}
	l.Log(ctx, event)
}

// LogSecretOperation logs a secret operation
func (l *JSONLogger) LogSecretOperation(ctx context.Context, eventType EventType, resource *ResourceInfo, outcome Outcome, message string) {
	event := &Event{
		Type:     eventType,
		Outcome:  outcome,
		Resource: resource,
		Message:  message,
	}
	l.Log(ctx, event)
}

// LogRotation logs a rotation event
func (l *JSONLogger) LogRotation(ctx context.Context, resource *ResourceInfo, outcome Outcome, oldVersion, newVersion string, err error) {
	event := &Event{
		Type:     EventTypeRotation,
		Outcome:  outcome,
		Resource: resource,
		Message:  fmt.Sprintf("Rotation from %s to %s", oldVersion, newVersion),
		Metadata: map[string]string{
			"oldVersion": oldVersion,
			"newVersion": newVersion,
		},
	}
	if err != nil {
		event.Error = err.Error()
	}
	l.Log(ctx, event)
}

// LogAttestation logs an attestation event
func (l *JSONLogger) LogAttestation(ctx context.Context, resource *ResourceInfo, actor *ActorInfo, outcome Outcome, message string, err error) {
	event := &Event{
		Type:     EventTypeAttestation,
		Outcome:  outcome,
		Resource: resource,
		Actor:    actor,
		Message:  message,
	}
	if err != nil {
		event.Error = err.Error()
	}
	l.Log(ctx, event)
}

// LogAuthFailure logs an authentication failure
func (l *JSONLogger) LogAuthFailure(ctx context.Context, resource *ResourceInfo, actor *ActorInfo, reason string) {
	event := &Event{
		Type:     EventTypeAuthFailure,
		Outcome:  OutcomeDenied,
		Resource: resource,
		Actor:    actor,
		Message:  reason,
	}
	l.Log(ctx, event)
}

// Close closes the logger
func (l *JSONLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true

	if closer, ok := l.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// NopLogger is a no-op logger for testing
type NopLogger struct{}

// NewNopLogger creates a new no-op logger
func NewNopLogger() *NopLogger {
	return &NopLogger{}
}

func (l *NopLogger) Log(ctx context.Context, event *Event) {}
func (l *NopLogger) LogBootstrap(ctx context.Context, resource *ResourceInfo, provider string, outcome Outcome, message string, err error) {
}
func (l *NopLogger) LogSecretOperation(ctx context.Context, eventType EventType, resource *ResourceInfo, outcome Outcome, message string) {
}
func (l *NopLogger) LogRotation(ctx context.Context, resource *ResourceInfo, outcome Outcome, oldVersion, newVersion string, err error) {
}
func (l *NopLogger) LogAttestation(ctx context.Context, resource *ResourceInfo, actor *ActorInfo, outcome Outcome, message string, err error) {
}
func (l *NopLogger) LogAuthFailure(ctx context.Context, resource *ResourceInfo, actor *ActorInfo, reason string) {
}
func (l *NopLogger) Close() error { return nil }

// MultiLogger logs to multiple loggers
type MultiLogger struct {
	loggers []Logger
}

// NewMultiLogger creates a logger that writes to multiple destinations
func NewMultiLogger(loggers ...Logger) *MultiLogger {
	return &MultiLogger{loggers: loggers}
}

func (l *MultiLogger) Log(ctx context.Context, event *Event) {
	for _, logger := range l.loggers {
		logger.Log(ctx, event)
	}
}

func (l *MultiLogger) LogBootstrap(ctx context.Context, resource *ResourceInfo, provider string, outcome Outcome, message string, err error) {
	for _, logger := range l.loggers {
		logger.LogBootstrap(ctx, resource, provider, outcome, message, err)
	}
}

func (l *MultiLogger) LogSecretOperation(ctx context.Context, eventType EventType, resource *ResourceInfo, outcome Outcome, message string) {
	for _, logger := range l.loggers {
		logger.LogSecretOperation(ctx, eventType, resource, outcome, message)
	}
}

func (l *MultiLogger) LogRotation(ctx context.Context, resource *ResourceInfo, outcome Outcome, oldVersion, newVersion string, err error) {
	for _, logger := range l.loggers {
		logger.LogRotation(ctx, resource, outcome, oldVersion, newVersion, err)
	}
}

func (l *MultiLogger) LogAttestation(ctx context.Context, resource *ResourceInfo, actor *ActorInfo, outcome Outcome, message string, err error) {
	for _, logger := range l.loggers {
		logger.LogAttestation(ctx, resource, actor, outcome, message, err)
	}
}

func (l *MultiLogger) LogAuthFailure(ctx context.Context, resource *ResourceInfo, actor *ActorInfo, reason string) {
	for _, logger := range l.loggers {
		logger.LogAuthFailure(ctx, resource, actor, reason)
	}
}

func (l *MultiLogger) Close() error {
	var lastErr error
	for _, logger := range l.loggers {
		if err := logger.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Global logger instance
var (
	globalLogger Logger = NewNopLogger()
	globalMu     sync.RWMutex
)

// SetGlobalLogger sets the global audit logger
func SetGlobalLogger(logger Logger) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLogger = logger
}

// GetGlobalLogger returns the global audit logger
func GetGlobalLogger() Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalLogger
}

// Log logs an audit event using the global logger
func Log(ctx context.Context, event *Event) {
	GetGlobalLogger().Log(ctx, event)
}

// LogBootstrap logs a bootstrap event using the global logger
func LogBootstrap(ctx context.Context, resource *ResourceInfo, provider string, outcome Outcome, message string, err error) {
	GetGlobalLogger().LogBootstrap(ctx, resource, provider, outcome, message, err)
}

// LogSecretOperation logs a secret operation using the global logger
func LogSecretOperation(ctx context.Context, eventType EventType, resource *ResourceInfo, outcome Outcome, message string) {
	GetGlobalLogger().LogSecretOperation(ctx, eventType, resource, outcome, message)
}

// LogRotation logs a rotation event using the global logger
func LogRotation(ctx context.Context, resource *ResourceInfo, outcome Outcome, oldVersion, newVersion string, err error) {
	GetGlobalLogger().LogRotation(ctx, resource, outcome, oldVersion, newVersion, err)
}

// LogAttestation logs an attestation event using the global logger
func LogAttestation(ctx context.Context, resource *ResourceInfo, actor *ActorInfo, outcome Outcome, message string, err error) {
	GetGlobalLogger().LogAttestation(ctx, resource, actor, outcome, message, err)
}

// LogAuthFailure logs an authentication failure using the global logger
func LogAuthFailure(ctx context.Context, resource *ResourceInfo, actor *ActorInfo, reason string) {
	GetGlobalLogger().LogAuthFailure(ctx, resource, actor, reason)
}
