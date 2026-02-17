//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	"github.com/larsenclose/genesis/internal/crypto"
	"github.com/larsenclose/genesis/internal/envelope"
	"github.com/larsenclose/genesis/internal/kms/mock"
	genesisv1alpha1 "github.com/larsenclose/genesis/pkg/api/v1alpha1"
)

var (
	k8sClient client.Client
	testNs    = "genesis-e2e-test"
)

func TestMain(m *testing.M) {
	// Setup
	if err := setup(); err != nil {
		panic(err)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	cleanup()

	os.Exit(code)
}

func setup() error {
	// Add genesis types to scheme
	if err := genesisv1alpha1.AddToScheme(scheme.Scheme); err != nil {
		return err
	}

	// Get the kubernetes client
	cfg, err := config.GetConfig()
	if err != nil {
		return err
	}

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		return err
	}

	// Create test namespace
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNs,
		},
	}
	if err := k8sClient.Create(context.Background(), ns); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	// Create flux-system namespace for secrets
	fluxNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "flux-system",
		},
	}
	if err := k8sClient.Create(context.Background(), fluxNs); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

func cleanup() {
	ctx := context.Background()

	// Delete test namespace
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNs,
		},
	}
	k8sClient.Delete(ctx, ns)
}

func TestGenesisBootstrapCRDExists(t *testing.T) {
	ctx := context.Background()

	// Try to list GenesisBootstrap resources - this will fail if CRD doesn't exist
	list := &genesisv1alpha1.GenesisBootstrapList{}
	err := k8sClient.List(ctx, list)
	require.NoError(t, err, "CRD should be installed")
}

func TestCreateGenesisBootstrap(t *testing.T) {
	ctx := context.Background()

	// Create a mock envelope for testing
	// In a real E2E test, this would use actual KMS credentials
	mockProvider := mock.NewProvider()
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, mockProvider, kp.PrivateKey)
	require.NoError(t, err)

	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-bootstrap",
			Namespace: testNs,
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "mock", // Would be aws-kms in real test
				Ciphertext: env.CiphertextB64,
				PublicKey:  kp.PublicKey,
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "test-sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	// Create the bootstrap
	err = k8sClient.Create(ctx, bootstrap)
	require.NoError(t, err)

	// Cleanup
	t.Cleanup(func() {
		k8sClient.Delete(ctx, bootstrap)
	})

	// Verify it was created
	created := &genesisv1alpha1.GenesisBootstrap{}
	err = k8sClient.Get(ctx, types.NamespacedName{
		Name:      "test-bootstrap",
		Namespace: testNs,
	}, created)
	require.NoError(t, err)

	assert.Equal(t, "mock", created.Spec.Envelope.Provider)
	assert.Equal(t, kp.PublicKey, created.Spec.Envelope.PublicKey)
}

func TestOperatorReconcilesBootstrap(t *testing.T) {
	// Skip if operator is not running
	t.Skip("Requires operator to be running with proper KMS credentials")

	ctx := context.Background()

	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "reconcile-test",
			Namespace: testNs,
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "aws-kms",
				Ciphertext: "test", // Would need real encrypted data
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

	// Create
	err := k8sClient.Create(ctx, bootstrap)
	require.NoError(t, err)

	t.Cleanup(func() {
		k8sClient.Delete(ctx, bootstrap)
	})

	// Wait for Ready condition
	err = wait.PollImmediate(time.Second, 30*time.Second, func() (bool, error) {
		updated := &genesisv1alpha1.GenesisBootstrap{}
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      "reconcile-test",
			Namespace: testNs,
		}, updated); err != nil {
			return false, err
		}

		for _, c := range updated.Status.Conditions {
			if c.Type == genesisv1alpha1.ConditionTypeReady && c.Status == metav1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})

	require.NoError(t, err, "Bootstrap should become Ready")
}

func TestSecretCreation(t *testing.T) {
	// Skip if operator is not running
	t.Skip("Requires operator to be running with proper KMS credentials")

	ctx := context.Background()

	// Wait for secret to be created
	secret := &corev1.Secret{}
	err := wait.PollImmediate(time.Second, 30*time.Second, func() (bool, error) {
		if err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      "sops-age",
			Namespace: "flux-system",
		}, secret); err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	})

	require.NoError(t, err, "Secret should be created")
	assert.Contains(t, secret.Data, "age.agekey")
	assert.NotEmpty(t, secret.Data["age.agekey"])
}

func TestBootstrapDeletion(t *testing.T) {
	ctx := context.Background()

	bootstrap := &genesisv1alpha1.GenesisBootstrap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "delete-test",
			Namespace: testNs,
		},
		Spec: genesisv1alpha1.GenesisBootstrapSpec{
			Envelope: genesisv1alpha1.EnvelopeSpec{
				Provider:   "mock",
				Ciphertext: "dGVzdA==",
			},
			Output: genesisv1alpha1.OutputSpec{
				SecretName:      "delete-test-secret",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	// Create
	err := k8sClient.Create(ctx, bootstrap)
	require.NoError(t, err)

	// Verify it exists
	created := &genesisv1alpha1.GenesisBootstrap{}
	err = k8sClient.Get(ctx, types.NamespacedName{
		Name:      "delete-test",
		Namespace: testNs,
	}, created)
	require.NoError(t, err)

	// Delete
	err = k8sClient.Delete(ctx, bootstrap)
	require.NoError(t, err)

	// Verify it's deleted
	err = wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		err := k8sClient.Get(ctx, types.NamespacedName{
			Name:      "delete-test",
			Namespace: testNs,
		}, created)
		if errors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
	require.NoError(t, err, "Bootstrap should be deleted")
}
