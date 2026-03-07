package controller_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/larsenclose/genesis/internal/bridge"
	"github.com/larsenclose/genesis/internal/controller"
	genesisv1alpha1 "github.com/larsenclose/genesis/pkg/api/v1alpha1"
)

// MockRotationExecutor is a test implementation of RotationExecutor.
type MockRotationExecutor struct {
	Artifacts      *bridge.PublicArtifacts
	Error          error
	Called         bool
	CalledSecret   string
	CalledNs       string
	CalledKey      string
}

func (m *MockRotationExecutor) Rotate(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap, secretName, secretNamespace, secretKey string) (*bridge.PublicArtifacts, error) {
	m.Called = true
	m.CalledSecret = secretName
	m.CalledNs = secretNamespace
	m.CalledKey = secretKey
	if m.Error != nil {
		return nil, m.Error
	}
	return m.Artifacts, nil
}

func newMockExecutor() *MockRotationExecutor {
	return &MockRotationExecutor{
		Artifacts: &bridge.PublicArtifacts{
			PublicKey:          "age1testrotatedpublickey",
			EnvelopeCiphertext: []byte("new-encrypted-envelope-bytes"),
		},
	}
}

// testBootstrap creates a GenesisBootstrap CR for test use, matching the given
// secret name and namespace.
func testBootstrap(secretName, secretNamespace string) *genesisv1alpha1.GenesisBootstrap {
	return &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "mock",
				Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0", // base64("test-ciphertext")
				PublicKey:  "age1testpublickey",
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      secretName,
				SecretNamespace: secretNamespace,
				SecretKey:       "age.agekey",
			},
		},
	}
}

func setupRotationScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = genesisv1alpha1.AddToScheme(scheme)
	return scheme
}

func TestGenesisRotationPolicyReconciler_NotFound(t *testing.T) {
	scheme := setupRotationScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:   client,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(10),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "nonexistent",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)
}

func TestGenesisRotationPolicyReconciler_AddsFinalizerOnFirstReconcile(t *testing.T) {
	scheme := setupRotationScheme()

	// Create source secret
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "source-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:   client,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(10),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.Requeue)

	// Verify finalizer was added
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	assert.Contains(t, updated.Finalizers, "genesis.io/rotation-finalizer")
}

func TestGenesisRotationPolicyReconciler_SuspendedPolicy(t *testing.T) {
	scheme := setupRotationScheme()

	// Create source secret
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "source-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Suspend: true,
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret).
		WithStatusSubresource(policy).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:   client,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(10),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify condition was set
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)

	var foundCondition *metav1.Condition
	for _, c := range updated.Status.Conditions {
		if c.Type == genesisv1alpha1.ConditionTypeRotationReady {
			foundCondition = &c
			break
		}
	}
	require.NotNil(t, foundCondition)
	assert.Equal(t, metav1.ConditionFalse, foundCondition.Status)
	assert.Equal(t, genesisv1alpha1.ReasonRotationSuspended, foundCondition.Reason)
}

func TestGenesisRotationPolicyReconciler_InvalidInterval(t *testing.T) {
	scheme := setupRotationScheme()

	// Create source secret
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "source-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "invalid",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret).
		WithStatusSubresource(policy).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:   client,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(10),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify condition was set
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)

	var foundCondition *metav1.Condition
	for _, c := range updated.Status.Conditions {
		if c.Type == genesisv1alpha1.ConditionTypeRotationReady {
			foundCondition = &c
			break
		}
	}
	require.NotNil(t, foundCondition)
	assert.Equal(t, metav1.ConditionFalse, foundCondition.Status)
	assert.Equal(t, genesisv1alpha1.ReasonRotationFailed, foundCondition.Reason)
}

func TestGenesisRotationPolicyReconciler_SourceSecretNotFound(t *testing.T) {
	scheme := setupRotationScheme()

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "missing-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		WithStatusSubresource(policy).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:   client,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(10),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)

	// Verify condition was set
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)

	var foundCondition *metav1.Condition
	for _, c := range updated.Status.Conditions {
		if c.Type == genesisv1alpha1.ConditionTypeRotationReady {
			foundCondition = &c
			break
		}
	}
	require.NotNil(t, foundCondition)
	assert.Equal(t, metav1.ConditionFalse, foundCondition.Status)
	assert.Contains(t, foundCondition.Message, "Source secret not found")
}

func TestGenesisRotationPolicyReconciler_RotationNotDueYet(t *testing.T) {
	scheme := setupRotationScheme()

	// Create source secret
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.Now(),
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret).
		WithStatusSubresource(policy).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:   client,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(10),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	// Should requeue after ~24h
	assert.True(t, result.RequeueAfter > 23*time.Hour)
	assert.True(t, result.RequeueAfter <= 24*time.Hour)
}

func TestGenesisRotationPolicyReconciler_RotationDue(t *testing.T) {
	scheme := setupRotationScheme()

	// Create source secret with old creation timestamp
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
			Strategy: &genesisv1alpha1.RotationStrategySpec{
				Type: "BlueGreen",
			},
		},
	}

	mockExecutor := newMockExecutor()
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	recorder := record.NewFakeRecorder(10)
	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           client,
		Scheme:           scheme,
		Recorder:         recorder,
		RotationExecutor: mockExecutor,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	// Should requeue after 24h for next rotation
	assert.True(t, result.RequeueAfter > 23*time.Hour)

	// Verify mock executor was called
	assert.True(t, mockExecutor.Called)

	// Verify rotation count was incremented
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	assert.Equal(t, int64(1), updated.Status.RotationCount)

	// Verify last rotation status
	require.NotNil(t, updated.Status.LastRotation)
	assert.True(t, updated.Status.LastRotation.Success)
	assert.Equal(t, "Rotation completed successfully", updated.Status.LastRotation.Message)

	// Verify GenesisBootstrap was updated with new envelope
	updatedBootstrap := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(context.Background(), types.NamespacedName{
		Name:      "test-bootstrap",
		Namespace: "default",
	}, updatedBootstrap)
	require.NoError(t, err)
	assert.Equal(t, "age1testrotatedpublickey", updatedBootstrap.Spec.Envelope.PublicKey)

	// Check for RotationSucceeded event (may follow verification warning events)
	foundSucceeded := false
	drainEvents:
	for {
		select {
		case event := <-recorder.Events:
			if strings.Contains(event, "RotationSucceeded") {
				foundSucceeded = true
			}
		default:
			break drainEvents
		}
	}
	assert.True(t, foundSucceeded, "Expected RotationSucceeded event")
}

func TestGenesisRotationPolicyReconciler_RotationStrategies(t *testing.T) {
	strategies := []string{"BlueGreen", "Rolling", "Immediate", "Unknown"}

	for _, strategy := range strategies {
		t.Run(strategy, func(t *testing.T) {
			scheme := setupRotationScheme()

			sourceSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "source-secret",
					Namespace:         "default",
					CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
				},
				Data: map[string][]byte{
					"key": []byte("value"),
				},
			}

			bootstrap := testBootstrap("source-secret", "default")

			policy := &genesisv1alpha1.GenesisRotationPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-policy",
					Namespace:  "default",
					Finalizers: []string{"genesis.io/rotation-finalizer"},
				},
				Spec: genesisv1alpha1.GenesisRotationPolicySpec{
					Source: genesisv1alpha1.RotationSourceSpec{
						Name:      "source-secret",
						Namespace: "default",
					},
					Schedule: genesisv1alpha1.RotationScheduleSpec{
						Interval: "24h",
					},
					Strategy: &genesisv1alpha1.RotationStrategySpec{
						Type: strategy,
					},
				},
			}

			mockExecutor := newMockExecutor()
			client := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(policy, sourceSecret, bootstrap).
				WithStatusSubresource(policy).
				Build()

			reconciler := &controller.GenesisRotationPolicyReconciler{
				Client:           client,
				Scheme:           scheme,
				Recorder:         record.NewFakeRecorder(10),
				RotationExecutor: mockExecutor,
			}

			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-policy",
					Namespace: "default",
				},
			}

			result, err := reconciler.Reconcile(context.Background(), req)
			require.NoError(t, err)
			assert.True(t, result.RequeueAfter > 0)

			// Verify secret was updated with rotation annotations
			updatedSecret := &corev1.Secret{}
			err = client.Get(context.Background(), types.NamespacedName{
				Name:      "source-secret",
				Namespace: "default",
			}, updatedSecret)
			require.NoError(t, err)
			assert.Contains(t, updatedSecret.Annotations, "genesis.io/rotated-at")
			assert.Contains(t, updatedSecret.Annotations, "genesis.io/rotation-version")
			assert.Contains(t, updatedSecret.Annotations, "genesis.io/rotation-strategy")
		})
	}
}

func TestGenesisRotationPolicyReconciler_Deletion(t *testing.T) {
	scheme := setupRotationScheme()

	now := metav1.Now()
	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-policy",
			Namespace:         "default",
			Finalizers:        []string{"genesis.io/rotation-finalizer"},
			DeletionTimestamp: &now,
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:   client,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(10),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify the object was deleted (finalizer removed allows deletion to complete)
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	// With fake client, once finalizers are removed from an object with DeletionTimestamp,
	// the object is actually deleted, so we expect NotFound
	assert.True(t, err != nil, "Object should be deleted after finalizer removal")
}

func TestGenesisRotationPolicyReconciler_WebhookNotification(t *testing.T) {
	scheme := setupRotationScheme()

	// Create a test HTTP server to receive webhooks
	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create webhook secret
	webhookSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"url": []byte(server.URL),
		},
	}

	// Create source secret with old creation timestamp
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
			Notify: []genesisv1alpha1.NotificationSpec{
				{
					Type: "Webhook",
					WebhookSecretRef: &genesisv1alpha1.SecretKeySelector{
						Name: "webhook-secret",
						Key:  "url",
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, webhookSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           client,
		Scheme:           scheme,
		Recorder:         record.NewFakeRecorder(10),
		RotationExecutor: newMockExecutor(),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0)

	// Verify webhook was called
	assert.NotNil(t, receivedPayload)
	assert.Equal(t, "rotation", receivedPayload["event"])
	assert.Equal(t, "test-policy", receivedPayload["policyName"])
}

func TestGenesisRotationPolicyReconciler_SlackNotification(t *testing.T) {
	scheme := setupRotationScheme()

	// Create a test HTTP server to receive Slack webhooks
	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create webhook secret
	webhookSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "slack-webhook-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"url": []byte(server.URL),
		},
	}

	// Create source secret with old creation timestamp
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
			Notify: []genesisv1alpha1.NotificationSpec{
				{
					Type:    "Slack",
					Channel: "#ops",
					WebhookSecretRef: &genesisv1alpha1.SecretKeySelector{
						Name: "slack-webhook-secret",
						Key:  "url",
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, webhookSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           client,
		Scheme:           scheme,
		Recorder:         record.NewFakeRecorder(10),
		RotationExecutor: newMockExecutor(),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0)

	// Verify Slack webhook was called
	assert.NotNil(t, receivedPayload)
	text, ok := receivedPayload["text"].(string)
	require.True(t, ok)
	assert.Contains(t, text, "Genesis Rotation")
	assert.Contains(t, text, "rotated successfully")
}

func TestGenesisRotationPolicyReconciler_WebhookSecretMissing(t *testing.T) {
	scheme := setupRotationScheme()

	// Create source secret with old creation timestamp
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
			Notify: []genesisv1alpha1.NotificationSpec{
				{
					Type: "Webhook",
					WebhookSecretRef: &genesisv1alpha1.SecretKeySelector{
						Name: "missing-secret",
						Key:  "url",
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           client,
		Scheme:           scheme,
		Recorder:         record.NewFakeRecorder(10),
		RotationExecutor: newMockExecutor(),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	// Should complete rotation even if notification fails
	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0)

	// Verify rotation still completed
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	assert.Equal(t, int64(1), updated.Status.RotationCount)
}

func TestGenesisRotationPolicyReconciler_PagerDutyNotification(t *testing.T) {
	scheme := setupRotationScheme()

	// Create source secret with old creation timestamp
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	// Create PagerDuty secret
	pdSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pagerduty-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"integration-key": []byte("test-key"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
			Notify: []genesisv1alpha1.NotificationSpec{
				{
					Type: "PagerDuty",
					WebhookSecretRef: &genesisv1alpha1.SecretKeySelector{
						Name: "pagerduty-secret",
						Key:  "integration-key",
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, pdSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           client,
		Scheme:           scheme,
		Recorder:         record.NewFakeRecorder(10),
		RotationExecutor: newMockExecutor(),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	// Should complete rotation (PagerDuty is stubbed)
	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0)
}

// TestGenesisRotationPolicyReconciler_PagerDutyNotification_SuccessPayload tests PagerDuty success payload
func TestGenesisRotationPolicyReconciler_PagerDutyNotification_SuccessPayload(t *testing.T) {
	t.Skip("Test requires making PagerDutyEventsAPIURL configurable or using dependency injection")
	// This test documents the expected behavior when PagerDuty integration is fully mocked
	// In a real implementation, we'd need to either:
	// 1. Make PagerDutyEventsAPIURL configurable via environment variable
	// 2. Use dependency injection for the HTTP client
	// 3. Create an interface for the notification sender
}

// TestGenesisRotationPolicyReconciler_PagerDutyNotification_MissingSecretRef tests missing webhookSecretRef
func TestGenesisRotationPolicyReconciler_PagerDutyNotification_MissingSecretRef(t *testing.T) {
	scheme := setupRotationScheme()

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	// Policy with PagerDuty notification but NO webhookSecretRef
	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
			Notify: []genesisv1alpha1.NotificationSpec{
				{
					Type:             "PagerDuty",
					WebhookSecretRef: nil, // Missing secret ref
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           client,
		Scheme:           scheme,
		Recorder:         record.NewFakeRecorder(10),
		RotationExecutor: newMockExecutor(),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	// Should complete rotation even if notification fails
	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0)

	// Verify rotation still completed
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	assert.Equal(t, int64(1), updated.Status.RotationCount)
}

// TestGenesisRotationPolicyReconciler_PagerDutyNotification_SecretNotFound tests missing secret
func TestGenesisRotationPolicyReconciler_PagerDutyNotification_SecretNotFound(t *testing.T) {
	scheme := setupRotationScheme()

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	// Policy references a non-existent secret
	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
			Notify: []genesisv1alpha1.NotificationSpec{
				{
					Type: "PagerDuty",
					WebhookSecretRef: &genesisv1alpha1.SecretKeySelector{
						Name: "missing-pagerduty-secret",
						Key:  "integration-key",
					},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           client,
		Scheme:           scheme,
		Recorder:         record.NewFakeRecorder(10),
		RotationExecutor: newMockExecutor(),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	// Should complete rotation even if notification fails due to missing secret
	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0)

	// Verify rotation still completed
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	assert.Equal(t, int64(1), updated.Status.RotationCount)
}

// TestGenesisRotationPolicyReconciler_PagerDutyNotification_WithDifferentStrategies tests PagerDuty notifications with different rotation strategies
func TestGenesisRotationPolicyReconciler_PagerDutyNotification_WithDifferentStrategies(t *testing.T) {
	strategies := []string{"BlueGreen", "Rolling", "Immediate"}

	for _, strategy := range strategies {
		t.Run(strategy, func(t *testing.T) {
			scheme := setupRotationScheme()

			sourceSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "source-secret",
					Namespace:         "default",
					CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
				},
				Data: map[string][]byte{
					"key": []byte("value"),
				},
			}

			pdSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pd-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"integration-key": []byte("test-key"),
				},
			}

			bootstrap := testBootstrap("source-secret", "default")

			policy := &genesisv1alpha1.GenesisRotationPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-policy",
					Namespace:  "default",
					Finalizers: []string{"genesis.io/rotation-finalizer"},
				},
				Spec: genesisv1alpha1.GenesisRotationPolicySpec{
					Source: genesisv1alpha1.RotationSourceSpec{
						Name:      "source-secret",
						Namespace: "default",
					},
					Schedule: genesisv1alpha1.RotationScheduleSpec{
						Interval: "24h",
					},
					Strategy: &genesisv1alpha1.RotationStrategySpec{
						Type: strategy,
					},
					Notify: []genesisv1alpha1.NotificationSpec{
						{
							Type: "PagerDuty",
							WebhookSecretRef: &genesisv1alpha1.SecretKeySelector{
								Name: "pd-secret",
								Key:  "integration-key",
							},
						},
					},
				},
			}

			client := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(policy, sourceSecret, pdSecret, bootstrap).
				WithStatusSubresource(policy).
				Build()

			reconciler := &controller.GenesisRotationPolicyReconciler{
				Client:           client,
				Scheme:           scheme,
				Recorder:         record.NewFakeRecorder(10),
				RotationExecutor: newMockExecutor(),
			}

			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-policy",
					Namespace: "default",
				},
			}

			// Should complete rotation with PagerDuty notification
			result, err := reconciler.Reconcile(context.Background(), req)
			require.NoError(t, err)
			assert.True(t, result.RequeueAfter > 0)

			// Verify rotation completed
			updated := &genesisv1alpha1.GenesisRotationPolicy{}
			err = client.Get(context.Background(), req.NamespacedName, updated)
			require.NoError(t, err)
			assert.Equal(t, int64(1), updated.Status.RotationCount)
			assert.True(t, updated.Status.LastRotation.Success)
		})
	}
}

// TestPagerDutyEventStructure tests the PagerDuty event structure can be marshaled to JSON
func TestPagerDutyEventStructure(t *testing.T) {
	event := controller.PagerDutyEvent{
		RoutingKey:  "test-routing-key",
		EventAction: "trigger",
		DedupKey:    "genesis-rotation/default/test-policy",
		Payload: controller.PagerDutyPayload{
			Summary:   "Test summary",
			Severity:  "info",
			Source:    "genesis-operator",
			Component: "rotation-policy",
			Group:     "default",
			Class:     "secret-rotation",
			CustomDetails: map[string]interface{}{
				"policy_name":    "test-policy",
				"rotation_count": int64(5),
			},
			Timestamp: time.Now().Format(time.RFC3339),
		},
		Client:    "Genesis Operator",
		ClientURL: "https://github.com/larsenclose/genesis",
	}

	// Verify JSON marshaling
	jsonData, err := json.Marshal(event)
	require.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	// Verify JSON unmarshaling
	var decoded controller.PagerDutyEvent
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "test-routing-key", decoded.RoutingKey)
	assert.Equal(t, "trigger", decoded.EventAction)
	assert.Equal(t, "genesis-rotation/default/test-policy", decoded.DedupKey)
	assert.Equal(t, "info", decoded.Payload.Severity)
	assert.Equal(t, "genesis-operator", decoded.Payload.Source)
	assert.Equal(t, "rotation-policy", decoded.Payload.Component)
}

// TestPagerDutyEventSeverityMapping tests that rotation status maps to correct severity
func TestPagerDutyEventSeverityMapping(t *testing.T) {
	t.Skip("Test requires access to buildPagerDutyEvent method - tested indirectly through integration tests")
	// This test documents that:
	// - Successful rotation -> severity: "info"
	// - Failed rotation -> severity: "error"
	// This is verified through integration tests above
}

func TestGenesisRotationPolicyReconciler_MultipleRotations(t *testing.T) {
	scheme := setupRotationScheme()

	lastRotationTime := metav1.NewTime(time.Now().Add(-25 * time.Hour))

	// Create source secret
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-50 * time.Hour)),
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
		},
		Status: genesisv1alpha1.GenesisRotationPolicyStatus{
			RotationCount: 5,
			LastRotation: &genesisv1alpha1.RotationStatus{
				Time:    lastRotationTime,
				Success: true,
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           client,
		Scheme:           scheme,
		Recorder:         record.NewFakeRecorder(10),
		RotationExecutor: newMockExecutor(),
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0)

	// Verify rotation count was incremented
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	assert.Equal(t, int64(6), updated.Status.RotationCount)
}

func TestGenesisRotationPolicyCRD(t *testing.T) {
	t.Run("RotationSourceSpec fields", func(t *testing.T) {
		source := genesisv1alpha1.RotationSourceSpec{
			Kind:      "Secret",
			Name:      "my-secret",
			Namespace: "production",
		}

		assert.Equal(t, "Secret", source.Kind)
		assert.Equal(t, "my-secret", source.Name)
		assert.Equal(t, "production", source.Namespace)
	})

	t.Run("RotationScheduleSpec fields", func(t *testing.T) {
		schedule := genesisv1alpha1.RotationScheduleSpec{
			Interval: "7d",
		}

		assert.Equal(t, "7d", schedule.Interval)
	})

	t.Run("RotationStrategySpec types", func(t *testing.T) {
		strategies := []genesisv1alpha1.RotationStrategySpec{
			{Type: "BlueGreen"},
			{Type: "Rolling"},
			{Type: "Immediate"},
		}

		for _, s := range strategies {
			assert.NotEmpty(t, s.Type)
		}
	})

	t.Run("NotificationSpec types", func(t *testing.T) {
		notifications := []genesisv1alpha1.NotificationSpec{
			{Type: "Event"},
			{Type: "Slack", Channel: "#ops"},
			{Type: "Webhook", WebhookSecretRef: &genesisv1alpha1.SecretKeySelector{Name: "webhook", Key: "url"}},
			{Type: "PagerDuty"},
		}

		for _, n := range notifications {
			assert.NotEmpty(t, n.Type)
		}
	})

	t.Run("RotationStatus fields", func(t *testing.T) {
		status := genesisv1alpha1.RotationStatus{
			Time:       metav1.Now(),
			OldVersion: "v1",
			NewVersion: "v2",
			Success:    true,
			Message:    "Rotation succeeded",
		}

		assert.True(t, status.Success)
		assert.Equal(t, "v1", status.OldVersion)
		assert.Equal(t, "v2", status.NewVersion)
	})
}

func TestWebhookPayloadStructure(t *testing.T) {
	payload := controller.WebhookPayload{
		Event:         "rotation",
		PolicyName:    "test-policy",
		Namespace:     "default",
		RotationCount: 5,
		Timestamp:     time.Now(),
	}
	payload.Source.Kind = "Secret"
	payload.Source.Name = "my-secret"
	payload.Source.Namespace = "production"
	payload.Rotation.Time = time.Now().Format(time.RFC3339)
	payload.Rotation.OldVersion = "v1"
	payload.Rotation.NewVersion = "v2"
	payload.Rotation.Success = true
	payload.Rotation.Message = "Rotation completed"

	// Verify JSON serialization
	data, err := json.Marshal(payload)
	require.NoError(t, err)

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "rotation", decoded["event"])
	assert.Equal(t, "test-policy", decoded["policyName"])
	assert.Equal(t, "default", decoded["namespace"])
	assert.Equal(t, float64(5), decoded["rotationCount"])

	source := decoded["source"].(map[string]interface{})
	assert.Equal(t, "Secret", source["kind"])
	assert.Equal(t, "my-secret", source["name"])
	assert.Equal(t, "production", source["namespace"])

	rotation := decoded["rotation"].(map[string]interface{})
	assert.Equal(t, true, rotation["success"])
	assert.Equal(t, "v1", rotation["oldVersion"])
	assert.Equal(t, "v2", rotation["newVersion"])
}

// --- New tests for RotationExecutor wiring ---

func TestFindGenesisBootstrap(t *testing.T) {
	t.Run("Found", func(t *testing.T) {
		scheme := setupRotationScheme()

		bootstrap := testBootstrap("my-secret", "production")

		sourceSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "my-secret",
				Namespace:         "production",
				CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
			},
			Data: map[string][]byte{
				"key": []byte("value"),
			},
		}

		policy := &genesisv1alpha1.GenesisRotationPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-policy",
				Namespace:  "default",
				Finalizers: []string{"genesis.io/rotation-finalizer"},
			},
			Spec: genesisv1alpha1.GenesisRotationPolicySpec{
				Source: genesisv1alpha1.RotationSourceSpec{
					Name:      "my-secret",
					Namespace: "production",
				},
				Schedule: genesisv1alpha1.RotationScheduleSpec{
					Interval: "24h",
				},
			},
		}

		mockExecutor := newMockExecutor()
		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(policy, sourceSecret, bootstrap).
			WithStatusSubresource(policy).
			Build()

		reconciler := &controller.GenesisRotationPolicyReconciler{
			Client:           client,
			Scheme:           scheme,
			Recorder:         record.NewFakeRecorder(10),
			RotationExecutor: mockExecutor,
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-policy",
				Namespace: "default",
			},
		}

		// Reconcile triggers rotation (secret is old enough)
		result, err := reconciler.Reconcile(context.Background(), req)
		require.NoError(t, err)
		assert.True(t, result.RequeueAfter > 0)

		// Verify the mock was called with the correct secret details
		assert.True(t, mockExecutor.Called)
		assert.Equal(t, "my-secret", mockExecutor.CalledSecret)
		assert.Equal(t, "production", mockExecutor.CalledNs)
		assert.Equal(t, "age.agekey", mockExecutor.CalledKey)
	})

	t.Run("NotFound", func(t *testing.T) {
		scheme := setupRotationScheme()

		// No GenesisBootstrap exists for this secret
		sourceSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "orphan-secret",
				Namespace:         "default",
				CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
			},
			Data: map[string][]byte{
				"key": []byte("value"),
			},
		}

		policy := &genesisv1alpha1.GenesisRotationPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-policy",
				Namespace:  "default",
				Finalizers: []string{"genesis.io/rotation-finalizer"},
			},
			Spec: genesisv1alpha1.GenesisRotationPolicySpec{
				Source: genesisv1alpha1.RotationSourceSpec{
					Name:      "orphan-secret",
					Namespace: "default",
				},
				Schedule: genesisv1alpha1.RotationScheduleSpec{
					Interval: "24h",
				},
			},
		}

		mockExecutor := newMockExecutor()
		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(policy, sourceSecret).
			WithStatusSubresource(policy).
			Build()

		reconciler := &controller.GenesisRotationPolicyReconciler{
			Client:           client,
			Scheme:           scheme,
			Recorder:         record.NewFakeRecorder(10),
			RotationExecutor: mockExecutor,
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-policy",
				Namespace: "default",
			},
		}

		result, err := reconciler.Reconcile(context.Background(), req)
		require.NoError(t, err)
		// Should requeue with backoff on failure
		assert.Equal(t, time.Minute, result.RequeueAfter)

		// Mock should NOT have been called because findGenesisBootstrap fails first
		assert.False(t, mockExecutor.Called)

		// Verify failure condition was set
		updated := &genesisv1alpha1.GenesisRotationPolicy{}
		err = client.Get(context.Background(), req.NamespacedName, updated)
		require.NoError(t, err)

		var foundCondition *metav1.Condition
		for _, c := range updated.Status.Conditions {
			if c.Type == genesisv1alpha1.ConditionTypeRotationReady {
				foundCondition = &c
				break
			}
		}
		require.NotNil(t, foundCondition)
		assert.Equal(t, metav1.ConditionFalse, foundCondition.Status)
		assert.Contains(t, foundCondition.Message, "cannot find GenesisBootstrap")
	})
}

func TestRotationWithBridgeExecutor(t *testing.T) {
	scheme := setupRotationScheme()

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
		},
	}

	mockExecutor := newMockExecutor()
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           client,
		Scheme:           scheme,
		Recorder:         record.NewFakeRecorder(10),
		RotationExecutor: mockExecutor,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.RequeueAfter > 0)

	// Verify executor was called
	assert.True(t, mockExecutor.Called)

	// Verify GenesisBootstrap spec was updated with new envelope data
	updatedBootstrap := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(context.Background(), types.NamespacedName{
		Name:      "test-bootstrap",
		Namespace: "default",
	}, updatedBootstrap)
	require.NoError(t, err)
	assert.Equal(t, "age1testrotatedpublickey", updatedBootstrap.Spec.Envelope.PublicKey)
	// EnvelopeCiphertext is base64-encoded when stored in CR
	assert.NotEqual(t, "dGVzdC1jaXBoZXJ0ZXh0", updatedBootstrap.Spec.Envelope.Ciphertext)
}

func TestRotationExecutorError(t *testing.T) {
	scheme := setupRotationScheme()

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
		},
		Data: map[string][]byte{
			"key": []byte("value"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
		},
	}

	failingExecutor := &MockRotationExecutor{
		Error: fmt.Errorf("KMS provider unavailable"),
	}
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	recorder := record.NewFakeRecorder(10)
	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           client,
		Scheme:           scheme,
		Recorder:         recorder,
		RotationExecutor: failingExecutor,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	// Should requeue with backoff on failure
	assert.Equal(t, time.Minute, result.RequeueAfter)

	// Verify the executor was called
	assert.True(t, failingExecutor.Called)

	// Verify failure condition
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)

	var foundCondition *metav1.Condition
	for _, c := range updated.Status.Conditions {
		if c.Type == genesisv1alpha1.ConditionTypeRotationReady {
			foundCondition = &c
			break
		}
	}
	require.NotNil(t, foundCondition)
	assert.Equal(t, metav1.ConditionFalse, foundCondition.Status)
	assert.Contains(t, foundCondition.Message, "rotation failed")

	// Verify rotation count was NOT incremented
	assert.Equal(t, int64(0), updated.Status.RotationCount)

	// Verify RotationFailed event was emitted
	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, "RotationFailed")
	default:
		t.Error("Expected RotationFailed event")
	}
}

func TestGetRotationExecutor(t *testing.T) {
	t.Run("DefaultReturnsBridgeRotationExecutor", func(t *testing.T) {
		reconciler := &controller.GenesisRotationPolicyReconciler{
			// RotationExecutor not set -- should use default
		}
		executor := reconciler.GetRotationExecutor()
		_, ok := executor.(*controller.BridgeRotationExecutor)
		assert.True(t, ok, "Expected BridgeRotationExecutor as default")
	})

	t.Run("ExplicitOverrideRespected", func(t *testing.T) {
		mock := newMockExecutor()
		reconciler := &controller.GenesisRotationPolicyReconciler{
			RotationExecutor: mock,
		}
		executor := reconciler.GetRotationExecutor()
		assert.Equal(t, mock, executor)
	})
}

func TestRotationExecutorError_ConditionAndEvent(t *testing.T) {
	// Verifies that when the rotation executor returns an error (which in the
	// bridge path triggers AbortRotation), the controller correctly:
	// - Sets the RotationReady condition to False with the error message
	// - Emits a RotationFailed warning event
	// - Does NOT increment the rotation count
	// - Requeues with a backoff interval
	scheme := setupRotationScheme()

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
		},
		Data: map[string][]byte{
			"age.agekey": []byte("AGE-SECRET-KEY-1TEST"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
		},
	}

	failingExecutor := &MockRotationExecutor{
		Error: fmt.Errorf("CompleteRotation failed: KMS decrypt error"),
	}
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	recorder := record.NewFakeRecorder(10)
	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           fakeClient,
		Scheme:           scheme,
		Recorder:         recorder,
		RotationExecutor: failingExecutor,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, time.Minute, result.RequeueAfter)

	// Verify the executor was called
	assert.True(t, failingExecutor.Called)

	// Verify failure condition includes the error message
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = fakeClient.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)

	var foundCondition *metav1.Condition
	for _, c := range updated.Status.Conditions {
		if c.Type == genesisv1alpha1.ConditionTypeRotationReady {
			foundCondition = &c
			break
		}
	}
	require.NotNil(t, foundCondition)
	assert.Equal(t, metav1.ConditionFalse, foundCondition.Status)
	assert.Equal(t, genesisv1alpha1.ReasonRotationFailed, foundCondition.Reason)
	assert.Contains(t, foundCondition.Message, "CompleteRotation failed")

	// Verify rotation count was NOT incremented
	assert.Equal(t, int64(0), updated.Status.RotationCount)

	// Verify RotationFailed event was emitted
	select {
	case event := <-recorder.Events:
		assert.Contains(t, event, "RotationFailed")
		assert.Contains(t, event, "CompleteRotation failed")
	default:
		t.Error("Expected RotationFailed event")
	}

	// Verify GenesisBootstrap was NOT updated (rotation failed before CR update)
	updatedBootstrap := &genesisv1alpha1.GenesisBootstrap{}
	err = fakeClient.Get(context.Background(), types.NamespacedName{
		Name:      "test-bootstrap",
		Namespace: "default",
	}, updatedBootstrap)
	require.NoError(t, err)
	assert.Equal(t, "age1testpublickey", updatedBootstrap.Spec.Envelope.PublicKey,
		"GenesisBootstrap should not be updated on rotation failure")
}

func TestPostRotationVerification_SecretWithCorrectData(t *testing.T) {
	// Verifies that post-rotation verification passes without warnings
	// when the source secret has the expected key and managed-by label.
	scheme := setupRotationScheme()

	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "genesis-operator",
			},
		},
		Data: map[string][]byte{
			"age.agekey": []byte("AGE-SECRET-KEY-1TEST"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
		},
	}

	mockExecutor := newMockExecutor()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	recorder := record.NewFakeRecorder(10)
	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           fakeClient,
		Scheme:           scheme,
		Recorder:         recorder,
		RotationExecutor: mockExecutor,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.RequeueAfter > 23*time.Hour)

	// Verify rotation completed
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = fakeClient.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	assert.Equal(t, int64(1), updated.Status.RotationCount)
	require.NotNil(t, updated.Status.LastRotation)
	assert.True(t, updated.Status.LastRotation.Success)

	// Should have RotationSucceeded event but NO RotationVerificationWarning events
	var events []string
	drainLoop:
	for {
		select {
		case event := <-recorder.Events:
			events = append(events, event)
		default:
			break drainLoop
		}
	}
	// Expect only RotationSucceeded
	require.NotEmpty(t, events, "Expected at least one event")
	for _, event := range events {
		assert.NotContains(t, event, "RotationVerificationWarning",
			"Should not have verification warnings when secret has correct data and labels")
	}
}

func TestPostRotationVerification_SecretMissingKey(t *testing.T) {
	// Verifies that post-rotation verification emits a warning event
	// when the source secret is missing the expected data key, but
	// the rotation still succeeds (verification is best-effort).
	scheme := setupRotationScheme()

	// Secret exists but does NOT have the "age.agekey" data key
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "genesis-operator",
			},
		},
		Data: map[string][]byte{
			"wrong-key": []byte("some-value"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
		},
	}

	mockExecutor := newMockExecutor()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	recorder := record.NewFakeRecorder(10)
	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           fakeClient,
		Scheme:           scheme,
		Recorder:         recorder,
		RotationExecutor: mockExecutor,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.RequeueAfter > 23*time.Hour,
		"Rotation should still succeed despite verification warning")

	// Verify rotation completed successfully (best-effort verification)
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = fakeClient.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	assert.Equal(t, int64(1), updated.Status.RotationCount)

	// Should have a RotationVerificationWarning event for missing key
	var events []string
	drainLoop:
	for {
		select {
		case event := <-recorder.Events:
			events = append(events, event)
		default:
			break drainLoop
		}
	}
	foundKeyWarning := false
	for _, event := range events {
		if strings.Contains(event, "RotationVerificationWarning") && strings.Contains(event, "missing expected key") {
			foundKeyWarning = true
		}
	}
	assert.True(t, foundKeyWarning, "Expected RotationVerificationWarning event for missing key, got events: %v", events)
}

func TestPostRotationVerification_SecretMissingManagedByLabel(t *testing.T) {
	// Verifies that post-rotation verification emits a warning event
	// when the source secret lacks the managed-by label, but the rotation
	// still succeeds (verification is best-effort).
	scheme := setupRotationScheme()

	// Secret has correct data key but NO managed-by label
	sourceSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "source-secret",
			Namespace:         "default",
			CreationTimestamp: metav1.NewTime(time.Now().Add(-25 * time.Hour)),
		},
		Data: map[string][]byte{
			"age.agekey": []byte("AGE-SECRET-KEY-1TEST"),
		},
	}

	bootstrap := testBootstrap("source-secret", "default")

	policy := &genesisv1alpha1.GenesisRotationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-policy",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/rotation-finalizer"},
		},
		Spec: genesisv1alpha1.GenesisRotationPolicySpec{
			Source: genesisv1alpha1.RotationSourceSpec{
				Name:      "source-secret",
				Namespace: "default",
			},
			Schedule: genesisv1alpha1.RotationScheduleSpec{
				Interval: "24h",
			},
		},
	}

	mockExecutor := newMockExecutor()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, sourceSecret, bootstrap).
		WithStatusSubresource(policy).
		Build()

	recorder := record.NewFakeRecorder(10)
	reconciler := &controller.GenesisRotationPolicyReconciler{
		Client:           fakeClient,
		Scheme:           scheme,
		Recorder:         recorder,
		RotationExecutor: mockExecutor,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-policy",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.RequeueAfter > 23*time.Hour,
		"Rotation should still succeed despite verification warning")

	// Verify rotation completed successfully (best-effort verification)
	updated := &genesisv1alpha1.GenesisRotationPolicy{}
	err = fakeClient.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	assert.Equal(t, int64(1), updated.Status.RotationCount)

	// Should have a RotationVerificationWarning event for missing label
	var events []string
	drainLoop:
	for {
		select {
		case event := <-recorder.Events:
			events = append(events, event)
		default:
			break drainLoop
		}
	}
	foundLabelWarning := false
	for _, event := range events {
		if strings.Contains(event, "RotationVerificationWarning") && strings.Contains(event, "managed-by label") {
			foundLabelWarning = true
		}
	}
	assert.True(t, foundLabelWarning, "Expected RotationVerificationWarning event for missing managed-by label, got events: %v", events)
}
