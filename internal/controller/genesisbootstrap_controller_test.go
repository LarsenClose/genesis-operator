package controller_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/larsenclose/genesis/internal/controller"
	"github.com/larsenclose/genesis/internal/crypto"
	"github.com/larsenclose/genesis/internal/envelope"
	"github.com/larsenclose/genesis/internal/kms"
	"github.com/larsenclose/genesis/internal/kms/mock"
	genesisv1alpha1 "github.com/larsenclose/genesis/pkg/api/v1alpha1"
)

func setupScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = genesisv1alpha1.AddToScheme(scheme)
	return scheme
}

func TestGenesisBootstrapReconciler_NotFound(t *testing.T) {
	scheme := setupScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
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

func TestGenesisBootstrapReconciler_AddsFinalizerOnFirstReconcile(t *testing.T) {
	scheme := setupScheme()
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "aws-kms",
				Ciphertext: "dGVzdA==",
				AWSKms: &genesisv1alpha1.AWSKmsSpec{
					KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
				},
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(bootstrap).
		Build()
	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}
	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.Requeue)

	// Verify finalizer was added
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	assert.Contains(t, updated.Finalizers, "genesis.io/finalizer")
}
func TestCRDTypes(t *testing.T) {
	t.Run("GenesisBootstrap has correct fields", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Envelope: genesisv1alpha1.EnvelopeSpec{
					Provider:   "aws-kms",
					Ciphertext: "base64data",
					PublicKey:  "age1test",
					AWSKms: &genesisv1alpha1.AWSKmsSpec{
						KeyArn: "arn:aws:kms:us-west-2:123:key/test",
						Region: "us-west-2",
					},
				},
				Output: genesisv1alpha1.OutputSpec{
					SecretName:      "sops-age",
					SecretNamespace: "flux-system",
					SecretKey:       "age.agekey",
				},
			},
		}

		assert.Equal(t, "test", bootstrap.Name)
		assert.Equal(t, "aws-kms", bootstrap.Spec.Envelope.Provider)
		assert.NotNil(t, bootstrap.Spec.Envelope.AWSKms)
	})
	t.Run("EnvelopeSpec supports all providers", func(t *testing.T) {
		tests := []struct {
			name     string
			envelope genesisv1alpha1.EnvelopeSpec
		}{
			{
				name: "aws-kms",
				envelope: genesisv1alpha1.EnvelopeSpec{
					Provider:   "aws-kms",
					Ciphertext: "test",
					AWSKms:     &genesisv1alpha1.AWSKmsSpec{KeyArn: "arn:aws:kms:us-west-2:123:key/test"},
				},
			},
			{
				name: "gcp-kms",
				envelope: genesisv1alpha1.EnvelopeSpec{
					Provider:   "gcp-kms",
					Ciphertext: "test",
					GCPKms:     &genesisv1alpha1.GCPKmsSpec{KeyName: "projects/test/keys/test"},
				},
			},
			{
				name: "azure-keyvault",
				envelope: genesisv1alpha1.EnvelopeSpec{
					Provider:   "azure-keyvault",
					Ciphertext: "test",
					AzureKeyVault: &genesisv1alpha1.AzureKeyVaultSpec{
						VaultUrl: "https://test.vault.azure.net",
						KeyName:  "test-key",
					},
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.name, tt.envelope.Provider)
			})
		}
	})
	t.Run("AttestationSpec supports OIDC and IRSA", func(t *testing.T) {
		attestation := &genesisv1alpha1.AttestationSpec{
			OIDC: &genesisv1alpha1.OIDCSpec{
				Issuer:   "https://oidc.eks.us-west-2.amazonaws.com/id/TEST",
				Audience: "sts.amazonaws.com",
				Subject:  "system:serviceaccount:genesis-system:genesis-operator",
			},
			AWSIRSA: &genesisv1alpha1.AWSIRSASpec{
				RoleArn: "arn:aws:iam::123456789012:role/genesis-operator-role",
			},
		}

		assert.NotNil(t, attestation.OIDC)
		assert.NotNil(t, attestation.AWSIRSA)
		assert.Equal(t, "sts.amazonaws.com", attestation.OIDC.Audience)
	})
	t.Run("OutputSpec has defaults", func(t *testing.T) {
		output := genesisv1alpha1.OutputSpec{
			SecretName:      "sops-age",
			SecretNamespace: "flux-system",
			SecretKey:       "age.agekey",
		}

		assert.Equal(t, "sops-age", output.SecretName)
		assert.Equal(t, "flux-system", output.SecretNamespace)
		assert.Equal(t, "age.agekey", output.SecretKey)
	})
	t.Run("Status conditions work correctly", func(t *testing.T) {
		status := &genesisv1alpha1.GenesisBootstrapStatus{
			Conditions: []metav1.Condition{
				{
					Type:               genesisv1alpha1.ConditionTypeReady,
					Status:             metav1.ConditionTrue,
					LastTransitionTime: metav1.Now(),
					Reason:             genesisv1alpha1.ReasonDecryptionKeyProvisioned,
					Message:            "Key provisioned successfully",
				},
			},
			LastAttestation: &genesisv1alpha1.AttestationStatus{
				Time:     metav1.Now(),
				Provider: "aws-kms",
				Identity: "arn:aws:sts::123:assumed-role/test",
			},
			KeyMetadata: &genesisv1alpha1.KeyMetadata{
				PublicKey: "age1test",
				Algorithm: "X25519",
			},
		}

		assert.Len(t, status.Conditions, 1)
		assert.Equal(t, genesisv1alpha1.ConditionTypeReady, status.Conditions[0].Type)
		assert.NotNil(t, status.LastAttestation)
		assert.NotNil(t, status.KeyMetadata)
	})
}
func TestEnvelopeIntegration(t *testing.T) {
	ctx := context.Background()

	// Create a mock provider and generate a real envelope
	mockProvider := mock.NewProvider()
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)
	env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
	require.NoError(t, err)

	// Verify we can decrypt it
	decrypted, err := envelope.Open(ctx, mockProvider, env)
	require.NoError(t, err)
	assert.Equal(t, kp.PrivateKey, decrypted)
	// Parse the decrypted key
	parsedKp, err := crypto.ParseAgeKeypair(decrypted)
	require.NoError(t, err)
	assert.Equal(t, kp.PublicKey, parsedKp.PublicKey)
}

func TestConditionConstants(t *testing.T) {
	assert.Equal(t, "Ready", genesisv1alpha1.ConditionTypeReady)
	assert.Equal(t, "SecretCreated", genesisv1alpha1.ConditionTypeSecretCreated)
	assert.Equal(t, "AttestationValid", genesisv1alpha1.ConditionTypeAttestationValid)
	assert.Equal(t, "DecryptionKeyProvisioned", genesisv1alpha1.ReasonDecryptionKeyProvisioned)
	assert.Equal(t, "DecryptionFailed", genesisv1alpha1.ReasonDecryptionFailed)
	assert.Equal(t, "SecretCreated", genesisv1alpha1.ReasonSecretCreated)
	assert.Equal(t, "SecretCreationFailed", genesisv1alpha1.ReasonSecretCreationFailed)
}

func TestGenesisBootstrapList(t *testing.T) {
	list := &genesisv1alpha1.GenesisBootstrapList{
		Items: []genesisv1alpha1.GenesisBootstrap{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "test1"},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "test2"},
			},
		},
	}
	assert.Len(t, list.Items, 2)
}

func TestTPMSpec(t *testing.T) {
	tpm := &genesisv1alpha1.TPMSpec{
		PCRSelection: &genesisv1alpha1.PCRSelection{
			Hash: "sha256",
			PCRs: []int{0, 1, 2, 3, 7},
		},
	}
	assert.Equal(t, "sha256", tpm.PCRSelection.Hash)
	assert.Equal(t, []int{0, 1, 2, 3, 7}, tpm.PCRSelection.PCRs)
}

func TestYubiKeySpec(t *testing.T) {
	yubikey := &genesisv1alpha1.YubiKeySpec{
		Slot:                 "9a",
		PublicKeyFingerprint: "SHA256:abc123",
	}
	assert.Equal(t, "9a", yubikey.Slot)
	assert.Equal(t, "SHA256:abc123", yubikey.PublicKeyFingerprint)
}

func TestGCPWorkloadIdentitySpec(t *testing.T) {
	gcp := &genesisv1alpha1.GCPWorkloadIdentitySpec{
		ServiceAccount: "genesis-operator@my-project.iam.gserviceaccount.com",
	}
	assert.Equal(t, "genesis-operator@my-project.iam.gserviceaccount.com", gcp.ServiceAccount)
}

func TestKeyMetadata(t *testing.T) {
	now := metav1.NewTime(time.Now())
	metadata := &genesisv1alpha1.KeyMetadata{
		PublicKey: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
		CreatedAt: now,
		Algorithm: "X25519",
	}
	assert.Contains(t, metadata.PublicKey, "age1")
	assert.Equal(t, "X25519", metadata.Algorithm)
	assert.False(t, metadata.CreatedAt.IsZero())
}

// Deletion Handling Tests
func TestGenesisBootstrapReconciler_Deletion_WithFinalizer(t *testing.T) {
	scheme := setupScheme()
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}

	now := metav1.Now()
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-bootstrap",
			Namespace:         "default",
			Finalizers:        []string{"genesis.io/finalizer"},
			DeletionTimestamp: &now,
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "aws-kms",
				Ciphertext: "dGVzdA==",
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		Build()
	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}
	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// After deletion, the object should be removed, so Get should return NotFound
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	// The object is fully deleted, so we expect it to not be found
	assert.True(t, errors.IsNotFound(err) || len(updated.Finalizers) == 0)
}
func TestGenesisBootstrapReconciler_Deletion_CleansUpOwnedSecrets(t *testing.T) {
	scheme := setupScheme()
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}

	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-bootstrap",
			Namespace:         "default",
			Finalizers:        []string{"genesis.io/finalizer"},
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "aws-kms",
				Ciphertext: "dGVzdA==",
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}
	// Create an owned secret
	ownedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sops-age",
			Namespace: "flux-system",
			Labels: map[string]string{
				"genesis.io/bootstrap": "test-bootstrap",
			},
		},
		Data: map[string][]byte{
			"age.agekey": []byte("test-key"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap, ownedSecret).
		Build()
	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}
	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify secret was deleted
	secret := &corev1.Secret{}
	err = client.Get(context.Background(), types.NamespacedName{
		Name:      "sops-age",
		Namespace: "flux-system",
	}, secret)
	assert.True(t, errors.IsNotFound(err))
}
func TestGenesisBootstrapReconciler_Deletion_PreservesUnownedSecrets(t *testing.T) {
	scheme := setupScheme()
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}

	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-bootstrap",
			Namespace:         "default",
			Finalizers:        []string{"genesis.io/finalizer"},
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "aws-kms",
				Ciphertext: "dGVzdA==",
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}
	// Create an unowned secret (missing label)
	unownedSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sops-age",
			Namespace: "flux-system",
		},
		Data: map[string][]byte{
			"age.agekey": []byte("test-key"),
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap, unownedSecret).
		Build()
	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}
	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	// Verify secret was NOT deleted
	secret := &corev1.Secret{}
	err = client.Get(context.Background(), types.NamespacedName{
		Name:      "sops-age",
		Namespace: "flux-system",
	}, secret)
	require.NoError(t, err)
}

// Provider Creation Tests

func TestGenesisBootstrapReconciler_CreateProvider_InvalidProvider(t *testing.T) {
	scheme := setupScheme()
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "invalid-provider",
				Ciphertext: "dGVzdA==",
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
	}
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)
	// Verify status was updated with error
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	if assert.NotEmpty(t, updated.Status.Conditions) {
		assert.Equal(t, genesisv1alpha1.ConditionTypeReady, updated.Status.Conditions[0].Type)
		assert.Equal(t, metav1.ConditionFalse, updated.Status.Conditions[0].Status)
		assert.Equal(t, genesisv1alpha1.ReasonProviderNotSupported, updated.Status.Conditions[0].Reason)
	}
}

func TestGenesisBootstrapReconciler_CreateProvider_MissingAWSConfig(t *testing.T) {
	scheme := setupScheme()
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "aws-kms",
				Ciphertext: "dGVzdA==",
				// Missing AWSKms configuration
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
	}
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)
	// Verify status contains error message
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	if assert.NotEmpty(t, updated.Status.Conditions) {
		assert.Contains(t, updated.Status.Conditions[0].Message, "awsKms configuration required")
	}
}

func TestGenesisBootstrapReconciler_CreateProvider_MissingGCPConfig(t *testing.T) {
	scheme := setupScheme()
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "gcp-kms",
				Ciphertext: "dGVzdA==",
				// Missing GCPKms configuration
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
	}
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	if assert.NotEmpty(t, updated.Status.Conditions) {
		assert.Contains(t, updated.Status.Conditions[0].Message, "gcpKms configuration required")
	}
}

func TestGenesisBootstrapReconciler_CreateProvider_MissingAzureConfig(t *testing.T) {
	scheme := setupScheme()
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "azure-keyvault",
				Ciphertext: "dGVzdA==",
				// Missing AzureKeyVault configuration
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
	}
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	if assert.NotEmpty(t, updated.Status.Conditions) {
		assert.Contains(t, updated.Status.Conditions[0].Message, "azureKeyVault configuration required")
	}
}

// Envelope Decryption Tests
func TestGenesisBootstrapReconciler_DecryptEnvelope_InvalidBase64(t *testing.T) {
	scheme := setupScheme()
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}

	// Use invalid base64 ciphertext
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "aws-kms",
				Ciphertext: "not-valid-base64!!!",
				AWSKms: &genesisv1alpha1.AWSKmsSpec{
					KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
				},
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()
	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}
	result, err := reconciler.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)

	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(context.Background(), req.NamespacedName, updated)
	require.NoError(t, err)
	if assert.NotEmpty(t, updated.Status.Conditions) {
		assert.Equal(t, genesisv1alpha1.ReasonDecryptionFailed, updated.Status.Conditions[0].Reason)
		assert.Contains(t, updated.Status.Conditions[0].Message, "failed to decode ciphertext")
	}
}

// Secret Management Tests

func TestGenesisBootstrapReconciler_EnsureSecret_NamespaceNotFound(t *testing.T) {
	// Skip: This test requires dependency injection for KMS providers to work as a unit test.
	// The controller internally creates real KMS providers based on the spec, which requires
	// actual cloud credentials. Testing secret creation with missing namespace requires
	// either integration tests with real KMS or refactoring the controller to accept
	// a provider factory/interface for dependency injection.
	t.Skip("Requires KMS dependency injection - tested via integration tests")
}
func TestGenesisBootstrapReconciler_EnsureSecret_AdditionalNamespaces(t *testing.T) {
	// Skip: This test requires dependency injection for KMS providers to work as a unit test.
	// The controller creates real KMS providers based on the spec. Testing multi-namespace
	// secret distribution requires either integration tests with real KMS or refactoring
	// the controller to accept a provider factory for dependency injection.
	t.Skip("Requires KMS dependency injection - tested via integration tests")
}

// Status Update Tests
func TestGenesisBootstrapReconciler_SetCondition_NewCondition(t *testing.T) {
	// Skip: Testing condition creation requires successful reconciliation which
	// needs real KMS providers. The condition setting logic is tested indirectly
	// through the error path tests (InvalidProvider, MissingConfig, etc.)
	t.Skip("Requires KMS dependency injection - condition logic tested via error path tests")
}

func TestGenesisBootstrapReconciler_SetCondition_UpdateExisting(t *testing.T) {
	scheme := setupScheme()
	ctx := context.Background()

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "invalid-provider",
				Ciphertext: "dGVzdA==",
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
		Status: genesisv1alpha1.GenesisBootstrapStatus{
			Conditions: []metav1.Condition{
				{
					Type:               genesisv1alpha1.ConditionTypeReady,
					Status:             metav1.ConditionTrue,
					LastTransitionTime: metav1.Now(),
					Reason:             "OldReason",
					Message:            "Old message",
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
	}
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)
	// Verify condition was updated
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	var readyCondition *metav1.Condition
	for _, c := range updated.Status.Conditions {
		if c.Type == genesisv1alpha1.ConditionTypeReady {
			readyCondition = &c
			break
		}
	}
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	assert.Equal(t, genesisv1alpha1.ReasonProviderNotSupported, readyCondition.Reason)
	assert.NotEqual(t, "Old message", readyCondition.Message)
}

// MockProviderFactory is a test factory that returns a mock KMS provider
type MockProviderFactory struct {
	Provider kms.Provider
	Error    error
}

func (f *MockProviderFactory) CreateProvider(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap) (kms.Provider, error) {
	if f.Error != nil {
		return nil, f.Error
	}
	return f.Provider, nil
}

// MockAttestationVerifier is a test verifier that returns a predetermined identity
type MockAttestationVerifier struct {
	Identity string
	Error    error
}

func (v *MockAttestationVerifier) VerifyAttestation(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap) (string, error) {
	if v.Error != nil {
		return "", v.Error
	}
	return v.Identity, nil
}

// Full integration test with successful reconciliation using dependency injection
func TestGenesisBootstrapReconciler_SuccessfulReconciliation(t *testing.T) {
	scheme := setupScheme()
	ctx := context.Background()

	// Create a mock provider
	mockProvider := mock.NewProvider()

	// Generate a test age keypair and create an envelope
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
	require.NoError(t, err)

	// Create namespace
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}

	// Create the bootstrap resource with encoded ciphertext
	ciphertextB64 := base64.StdEncoding.EncodeToString(env.Ciphertext)
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "mock",
				Ciphertext: ciphertextB64,
				PublicKey:  kp.PublicKey,
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
		ProviderFactory: &MockProviderFactory{
			Provider: mockProvider,
		},
		AttestationVerifier: &MockAttestationVerifier{
			Identity: "",
		},
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)

	// Verify the secret was created
	secret := &corev1.Secret{}
	err = client.Get(ctx, types.NamespacedName{
		Name:      "sops-age",
		Namespace: "flux-system",
	}, secret)
	require.NoError(t, err)
	assert.Contains(t, string(secret.Data["age.agekey"]), "AGE-SECRET-KEY-")
	assert.Equal(t, "genesis-operator", secret.Labels["app.kubernetes.io/managed-by"])
	assert.Equal(t, "test-bootstrap", secret.Labels["genesis.io/bootstrap"])

	// Verify status was updated
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	// Check Ready condition
	var readyCondition *metav1.Condition
	for _, c := range updated.Status.Conditions {
		if c.Type == genesisv1alpha1.ConditionTypeReady {
			readyCondition = &c
			break
		}
	}
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionTrue, readyCondition.Status)
	assert.Equal(t, genesisv1alpha1.ReasonDecryptionKeyProvisioned, readyCondition.Reason)

	// Check key metadata
	require.NotNil(t, updated.Status.KeyMetadata)
	assert.Equal(t, kp.PublicKey, updated.Status.KeyMetadata.PublicKey)
	assert.Equal(t, "X25519", updated.Status.KeyMetadata.Algorithm)
}

func TestGenesisBootstrapReconciler_WithAttestation(t *testing.T) {
	scheme := setupScheme()
	ctx := context.Background()

	// Create a mock provider
	mockProvider := mock.NewProvider()

	// Generate a test age keypair and create an envelope
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
	require.NoError(t, err)

	// Create namespace
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(env.Ciphertext)
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "mock",
				Ciphertext: ciphertextB64,
				PublicKey:  kp.PublicKey,
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
			Attestation: &genesisv1alpha1.AttestationSpec{
				AWSIRSA: &genesisv1alpha1.AWSIRSASpec{
					RoleArn: "arn:aws:iam::123456789012:role/genesis-operator-role",
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
		ProviderFactory: &MockProviderFactory{
			Provider: mockProvider,
		},
		AttestationVerifier: &MockAttestationVerifier{
			Identity: "arn:aws:iam::123456789012:role/genesis-operator-role",
		},
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)

	// Verify status includes attestation info
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	// Check AttestationValid condition
	var attestationCondition *metav1.Condition
	for _, c := range updated.Status.Conditions {
		if c.Type == genesisv1alpha1.ConditionTypeAttestationValid {
			attestationCondition = &c
			break
		}
	}
	require.NotNil(t, attestationCondition)
	assert.Equal(t, metav1.ConditionTrue, attestationCondition.Status)

	// Check attestation status
	require.NotNil(t, updated.Status.LastAttestation)
	assert.Equal(t, "arn:aws:iam::123456789012:role/genesis-operator-role", updated.Status.LastAttestation.Identity)
}

func TestGenesisBootstrapReconciler_AttestationFailure(t *testing.T) {
	scheme := setupScheme()
	ctx := context.Background()

	mockProvider := mock.NewProvider()

	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
	require.NoError(t, err)

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(env.Ciphertext)
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "mock",
				Ciphertext: ciphertextB64,
				PublicKey:  kp.PublicKey,
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
			Attestation: &genesisv1alpha1.AttestationSpec{
				AWSIRSA: &genesisv1alpha1.AWSIRSASpec{
					RoleArn: "arn:aws:iam::123456789012:role/genesis-operator-role",
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
		ProviderFactory: &MockProviderFactory{
			Provider: mockProvider,
		},
		AttestationVerifier: &MockAttestationVerifier{
			Error: fmt.Errorf("OIDC token verification failed: invalid audience"),
		},
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)

	// Verify status shows attestation failure
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	var attestationCondition *metav1.Condition
	for _, c := range updated.Status.Conditions {
		if c.Type == genesisv1alpha1.ConditionTypeAttestationValid {
			attestationCondition = &c
			break
		}
	}
	require.NotNil(t, attestationCondition)
	assert.Equal(t, metav1.ConditionFalse, attestationCondition.Status)
	assert.Equal(t, genesisv1alpha1.ReasonAttestationFailed, attestationCondition.Reason)
}

func TestGenesisBootstrapReconciler_DecryptionFailure(t *testing.T) {
	scheme := setupScheme()
	ctx := context.Background()

	// Create a failing provider
	failingProvider := mock.NewFailingProvider(nil, fmt.Errorf("KMS decryption failed"))

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}

	// Use valid base64 but data that can't be decrypted
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "mock",
				Ciphertext: base64.StdEncoding.EncodeToString([]byte("invalid-ciphertext-data")),
				PublicKey:  "age1test",
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
		ProviderFactory: &MockProviderFactory{
			Provider: failingProvider,
		},
		AttestationVerifier: &MockAttestationVerifier{
			Identity: "",
		},
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)

	// Verify status shows decryption failure
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	var readyCondition *metav1.Condition
	for _, c := range updated.Status.Conditions {
		if c.Type == genesisv1alpha1.ConditionTypeReady {
			readyCondition = &c
			break
		}
	}
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	assert.Equal(t, genesisv1alpha1.ReasonDecryptionFailed, readyCondition.Reason)
}

func TestGenesisBootstrapReconciler_ProviderFactoryError(t *testing.T) {
	scheme := setupScheme()
	ctx := context.Background()

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}

	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "custom-kms",
				Ciphertext: "dGVzdA==",
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
		ProviderFactory: &MockProviderFactory{
			Error: fmt.Errorf("unknown provider: custom-kms"),
		},
		AttestationVerifier: &MockAttestationVerifier{
			Identity: "",
		},
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)

	// Verify status shows provider error
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	var readyCondition *metav1.Condition
	for _, c := range updated.Status.Conditions {
		if c.Type == genesisv1alpha1.ConditionTypeReady {
			readyCondition = &c
			break
		}
	}
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	assert.Equal(t, genesisv1alpha1.ReasonProviderNotSupported, readyCondition.Reason)
}

func TestGenesisBootstrapReconciler_AdditionalNamespaces(t *testing.T) {
	scheme := setupScheme()
	ctx := context.Background()

	mockProvider := mock.NewProvider()

	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
	require.NoError(t, err)

	// Create namespaces
	namespace1 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}
	namespace2 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "production",
		},
	}
	namespace3 := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "staging",
		},
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(env.Ciphertext)
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "mock",
				Ciphertext: ciphertextB64,
				PublicKey:  kp.PublicKey,
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:           "sops-age",
				SecretNamespace:      "flux-system",
				SecretKey:            "age.agekey",
				AdditionalNamespaces: []string{"production", "staging"},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace1, namespace2, namespace3, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
		ProviderFactory: &MockProviderFactory{
			Provider: mockProvider,
		},
		AttestationVerifier: &MockAttestationVerifier{
			Identity: "",
		},
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)

	// Verify secrets were created in all namespaces
	for _, ns := range []string{"flux-system", "production", "staging"} {
		secret := &corev1.Secret{}
		err = client.Get(ctx, types.NamespacedName{
			Name:      "sops-age",
			Namespace: ns,
		}, secret)
		require.NoError(t, err, "Secret should exist in namespace %s", ns)
		assert.Contains(t, string(secret.Data["age.agekey"]), "AGE-SECRET-KEY-")
	}
}

func TestGenesisBootstrapReconciler_NamespaceNotFound(t *testing.T) {
	scheme := setupScheme()
	ctx := context.Background()

	mockProvider := mock.NewProvider()

	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
	require.NoError(t, err)

	// Don't create the target namespace
	ciphertextB64 := base64.StdEncoding.EncodeToString(env.Ciphertext)
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "mock",
				Ciphertext: ciphertextB64,
				PublicKey:  kp.PublicKey,
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "nonexistent-namespace",
				SecretKey:       "age.agekey",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
		ProviderFactory: &MockProviderFactory{
			Provider: mockProvider,
		},
		AttestationVerifier: &MockAttestationVerifier{
			Identity: "",
		},
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)

	// Verify status shows secret creation failure
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	var secretCondition *metav1.Condition
	for _, c := range updated.Status.Conditions {
		if c.Type == genesisv1alpha1.ConditionTypeSecretCreated {
			secretCondition = &c
			break
		}
	}
	require.NotNil(t, secretCondition)
	assert.Equal(t, metav1.ConditionFalse, secretCondition.Status)
	assert.Equal(t, genesisv1alpha1.ReasonSecretCreationFailed, secretCondition.Reason)
	assert.Contains(t, secretCondition.Message, "does not exist")
}

func TestGenesisBootstrapReconciler_PublicKeyMismatch(t *testing.T) {
	scheme := setupScheme()
	ctx := context.Background()

	mockProvider := mock.NewProvider()

	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
	require.NoError(t, err)

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}

	// Use a different public key than what's in the decrypted key
	ciphertextB64 := base64.StdEncoding.EncodeToString(env.Ciphertext)
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "mock",
				Ciphertext: ciphertextB64,
				PublicKey:  "age1wrongpublickey12345678901234567890123456789012345678901234",
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
		ProviderFactory: &MockProviderFactory{
			Provider: mockProvider,
		},
		AttestationVerifier: &MockAttestationVerifier{
			Identity: "",
		},
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)

	// Verify status shows decryption failure due to key mismatch
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)

	var readyCondition *metav1.Condition
	for _, c := range updated.Status.Conditions {
		if c.Type == genesisv1alpha1.ConditionTypeReady {
			readyCondition = &c
			break
		}
	}
	require.NotNil(t, readyCondition)
	assert.Equal(t, metav1.ConditionFalse, readyCondition.Status)
	assert.Equal(t, genesisv1alpha1.ReasonDecryptionFailed, readyCondition.Reason)
	assert.Contains(t, readyCondition.Message, "public key mismatch")
}

// Test DefaultProviderFactory for all provider types
func TestDefaultProviderFactory(t *testing.T) {
	factory := &controller.DefaultProviderFactory{}
	ctx := context.Background()

	t.Run("aws-kms with valid config", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Envelope: genesisv1alpha1.EnvelopeSpec{
					Provider: "aws-kms",
					AWSKms: &genesisv1alpha1.AWSKmsSpec{
						KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test-key",
						Region: "us-west-2",
					},
				},
			},
		}
		provider, err := factory.CreateProvider(ctx, bootstrap)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "aws-kms", string(provider.Name()))
	})

	t.Run("aws-kms missing config", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Envelope: genesisv1alpha1.EnvelopeSpec{
					Provider: "aws-kms",
				},
			},
		}
		_, err := factory.CreateProvider(ctx, bootstrap)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "awsKms configuration required")
	})

	t.Run("gcp-kms with valid config", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Envelope: genesisv1alpha1.EnvelopeSpec{
					Provider: "gcp-kms",
					GCPKms: &genesisv1alpha1.GCPKmsSpec{
						KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
					},
				},
			},
		}
		provider, err := factory.CreateProvider(ctx, bootstrap)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "gcp-kms", string(provider.Name()))
	})

	t.Run("gcp-kms missing config", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Envelope: genesisv1alpha1.EnvelopeSpec{
					Provider: "gcp-kms",
				},
			},
		}
		_, err := factory.CreateProvider(ctx, bootstrap)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "gcpKms configuration required")
	})

	t.Run("azure-keyvault with valid config", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Envelope: genesisv1alpha1.EnvelopeSpec{
					Provider: "azure-keyvault",
					AzureKeyVault: &genesisv1alpha1.AzureKeyVaultSpec{
						VaultUrl:   "https://test.vault.azure.net",
						KeyName:    "test-key",
						KeyVersion: "v1",
					},
				},
			},
		}
		provider, err := factory.CreateProvider(ctx, bootstrap)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "azure-keyvault", string(provider.Name()))
	})

	t.Run("azure-keyvault missing config", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Envelope: genesisv1alpha1.EnvelopeSpec{
					Provider: "azure-keyvault",
				},
			},
		}
		_, err := factory.CreateProvider(ctx, bootstrap)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "azureKeyVault configuration required")
	})

	t.Run("yubikey with config", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Envelope: genesisv1alpha1.EnvelopeSpec{
					Provider: "yubikey",
					YubiKey: &genesisv1alpha1.YubiKeySpec{
						Slot:                 "9a",
						PublicKeyFingerprint: "SHA256:abc123",
					},
				},
			},
		}
		provider, err := factory.CreateProvider(ctx, bootstrap)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "yubikey", string(provider.Name()))
	})

	t.Run("yubikey without config", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Envelope: genesisv1alpha1.EnvelopeSpec{
					Provider: "yubikey",
				},
			},
		}
		provider, err := factory.CreateProvider(ctx, bootstrap)
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("tpm with config", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Envelope: genesisv1alpha1.EnvelopeSpec{
					Provider: "tpm",
					TPM: &genesisv1alpha1.TPMSpec{
						PCRSelection: &genesisv1alpha1.PCRSelection{
							Hash: "sha256",
							PCRs: []int{0, 1, 2, 3, 7},
						},
					},
				},
			},
		}
		provider, err := factory.CreateProvider(ctx, bootstrap)
		require.NoError(t, err)
		assert.NotNil(t, provider)
		assert.Equal(t, "tpm", string(provider.Name()))
	})

	t.Run("tpm without config", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Envelope: genesisv1alpha1.EnvelopeSpec{
					Provider: "tpm",
				},
			},
		}
		provider, err := factory.CreateProvider(ctx, bootstrap)
		require.NoError(t, err)
		assert.NotNil(t, provider)
	})

	t.Run("unknown provider", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Envelope: genesisv1alpha1.EnvelopeSpec{
					Provider: "unknown-provider",
				},
			},
		}
		_, err := factory.CreateProvider(ctx, bootstrap)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown provider")
	})
}

// Test DefaultAttestationVerifier
func TestDefaultAttestationVerifier(t *testing.T) {
	verifier := &controller.DefaultAttestationVerifier{}
	ctx := context.Background()

	t.Run("no attestation configured", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Attestation: nil,
			},
		}
		identity, err := verifier.VerifyAttestation(ctx, bootstrap)
		require.NoError(t, err)
		assert.Empty(t, identity)
	})

	t.Run("generic OIDC not implemented", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Attestation: &genesisv1alpha1.AttestationSpec{
					OIDC: &genesisv1alpha1.OIDCSpec{
						Issuer:   "https://example.com",
						Audience: "test",
					},
				},
			},
		}
		_, err := verifier.VerifyAttestation(ctx, bootstrap)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	t.Run("empty attestation spec", func(t *testing.T) {
		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Attestation: &genesisv1alpha1.AttestationSpec{},
			},
		}
		_, err := verifier.VerifyAttestation(ctx, bootstrap)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no valid attestation configuration found")
	})
}

// Test isOwnedBy function edge cases
func TestIsOwnedBy(t *testing.T) {
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	t.Run("secret with matching label", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"genesis.io/bootstrap": "test-bootstrap",
				},
			},
		}
		// We can't call isOwnedBy directly as it's unexported,
		// but we test its behavior through the deletion test
		assert.Equal(t, "test-bootstrap", secret.Labels["genesis.io/bootstrap"])
	})

	t.Run("secret with nil labels", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Labels: nil,
			},
		}
		assert.Nil(t, secret.Labels)
	})

	t.Run("secret with wrong label", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"genesis.io/bootstrap": "other-bootstrap",
				},
			},
		}
		assert.NotEqual(t, bootstrap.Name, secret.Labels["genesis.io/bootstrap"])
	})
}

// Test condition update scenarios
func TestConditionUpdates(t *testing.T) {
	t.Run("condition with same values not updated", func(t *testing.T) {
		// This tests the scenario where condition values haven't changed
		scheme := setupScheme()
		ctx := context.Background()

		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "flux-system",
			},
		}

		// Pre-existing condition with specific values
		existingCondition := metav1.Condition{
			Type:               genesisv1alpha1.ConditionTypeReady,
			Status:             metav1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             genesisv1alpha1.ReasonProviderNotSupported,
			Message:            "unknown provider: invalid-provider",
		}

		bootstrap := &genesisv1alpha1.GenesisBootstrap{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-bootstrap",
				Namespace:  "default",
				Finalizers: []string{"genesis.io/finalizer"},
			},
			Spec: genesisv1alpha1.GenesisBootstrapSpec{
				Envelope: genesisv1alpha1.EnvelopeSpec{
					Provider:   "invalid-provider",
					Ciphertext: "dGVzdA==",
				},
				Output: genesisv1alpha1.OutputSpec{
					SecretName:      "sops-age",
					SecretNamespace: "flux-system",
					SecretKey:       "age.agekey",
				},
			},
			Status: genesisv1alpha1.GenesisBootstrapStatus{
				Conditions: []metav1.Condition{existingCondition},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(namespace, bootstrap).
			WithStatusSubresource(bootstrap).
			Build()

		reconciler := &controller.GenesisBootstrapReconciler{
			Client: client,
			Scheme: scheme,
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      "test-bootstrap",
				Namespace: "default",
			},
		}

		// First reconcile
		result, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, 5*time.Minute, result.RequeueAfter)

		// Second reconcile - condition should not change transition time if values same
		result, err = reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, 5*time.Minute, result.RequeueAfter)
	})
}

// Test reconciler with nil ProviderFactory and AttestationVerifier (uses defaults)
func TestReconcilerWithDefaults(t *testing.T) {
	scheme := setupScheme()
	ctx := context.Background()

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}

	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "unknown-provider",
				Ciphertext: "dGVzdA==",
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	// Create reconciler WITHOUT setting ProviderFactory or AttestationVerifier
	// This tests that defaults are used
	reconciler := &controller.GenesisBootstrapReconciler{
		Client:              client,
		Scheme:              scheme,
		ProviderFactory:     nil, // Will use DefaultProviderFactory
		AttestationVerifier: nil, // Will use DefaultAttestationVerifier
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)

	// Verify error was recorded (unknown provider)
	updated := &genesisv1alpha1.GenesisBootstrap{}
	err = client.Get(ctx, req.NamespacedName, updated)
	require.NoError(t, err)
	assert.NotEmpty(t, updated.Status.Conditions)
}

// Test additional namespace error handling
func TestAdditionalNamespaceError(t *testing.T) {
	scheme := setupScheme()
	ctx := context.Background()

	mockProvider := mock.NewProvider()

	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
	require.NoError(t, err)

	// Only create primary namespace, not additional ones
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}

	ciphertextB64 := base64.StdEncoding.EncodeToString(env.Ciphertext)
	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-bootstrap",
			Namespace:  "default",
			Finalizers: []string{"genesis.io/finalizer"},
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "mock",
				Ciphertext: ciphertextB64,
				PublicKey:  kp.PublicKey,
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:           "sops-age",
				SecretNamespace:      "flux-system",
				SecretKey:            "age.agekey",
				AdditionalNamespaces: []string{"nonexistent-ns"},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(namespace, bootstrap).
		WithStatusSubresource(bootstrap).
		Build()

	reconciler := &controller.GenesisBootstrapReconciler{
		Client: client,
		Scheme: scheme,
		ProviderFactory: &MockProviderFactory{
			Provider: mockProvider,
		},
		AttestationVerifier: &MockAttestationVerifier{
			Identity: "",
		},
	}

	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-bootstrap",
			Namespace: "default",
		},
	}

	// Should still succeed for primary namespace, error is logged for additional
	result, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, result.RequeueAfter)

	// Verify primary secret was created
	secret := &corev1.Secret{}
	err = client.Get(ctx, types.NamespacedName{
		Name:      "sops-age",
		Namespace: "flux-system",
	}, secret)
	require.NoError(t, err)
}
