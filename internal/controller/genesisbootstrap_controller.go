package controller

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/larsenclose/genesis/internal/bridge"
	awsidentity "github.com/larsenclose/genesis/internal/identity/aws"
	gcpidentity "github.com/larsenclose/genesis/internal/identity/gcp"
	"github.com/larsenclose/genesis/internal/identity/github"
	"github.com/larsenclose/genesis/internal/kms"
	"github.com/larsenclose/genesis/internal/kms/awskms"
	"github.com/larsenclose/genesis/internal/kms/azurekv"
	"github.com/larsenclose/genesis/internal/kms/gcpkms"
	kmsmock "github.com/larsenclose/genesis/internal/kms/mock"
	"github.com/larsenclose/genesis/internal/kms/ocivault"
	"github.com/larsenclose/genesis/internal/kms/tpm"
	"github.com/larsenclose/genesis/internal/kms/yubikey"
	genesisv1alpha1 "github.com/larsenclose/genesis/pkg/api/v1alpha1"
)

const (
	finalizerName = "genesis.io/finalizer"
	requeueAfter  = 5 * time.Minute
)

// ProviderFactory creates KMS providers based on GenesisBootstrap specs.
// This interface allows dependency injection for testing.
type ProviderFactory interface {
	CreateProvider(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap) (kms.Provider, error)
}

// DefaultProviderFactory creates real KMS providers
type DefaultProviderFactory struct{}

// CreateProvider implements ProviderFactory for production use
func (f *DefaultProviderFactory) CreateProvider(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap) (kms.Provider, error) {
	switch bootstrap.Spec.Envelope.Provider {
	case "aws-kms":
		if bootstrap.Spec.Envelope.AWSKms == nil {
			return nil, fmt.Errorf("awsKms configuration required for aws-kms provider")
		}
		return awskms.NewProvider(awskms.Options{
			KeyArn: bootstrap.Spec.Envelope.AWSKms.KeyArn,
			Region: bootstrap.Spec.Envelope.AWSKms.Region,
		})

	case "gcp-kms":
		if bootstrap.Spec.Envelope.GCPKms == nil {
			return nil, fmt.Errorf("gcpKms configuration required for gcp-kms provider")
		}
		return gcpkms.NewProvider(gcpkms.Options{
			KeyName: bootstrap.Spec.Envelope.GCPKms.KeyName,
		})

	case "azure-keyvault":
		if bootstrap.Spec.Envelope.AzureKeyVault == nil {
			return nil, fmt.Errorf("azureKeyVault configuration required for azure-keyvault provider")
		}
		return azurekv.NewProvider(azurekv.Options{
			VaultURL:   bootstrap.Spec.Envelope.AzureKeyVault.VaultUrl,
			KeyName:    bootstrap.Spec.Envelope.AzureKeyVault.KeyName,
			KeyVersion: bootstrap.Spec.Envelope.AzureKeyVault.KeyVersion,
		})

	case "oci-vault":
		if bootstrap.Spec.Envelope.OCIVault == nil {
			return nil, fmt.Errorf("ociVault configuration required for oci-vault provider")
		}
		return ocivault.NewProvider(ocivault.Options{
			KeyOCID:        bootstrap.Spec.Envelope.OCIVault.KeyOCID,
			CryptoEndpoint: bootstrap.Spec.Envelope.OCIVault.CryptoEndpoint,
		})

	case "yubikey":
		opts := yubikey.Options{}
		if bootstrap.Spec.Envelope.YubiKey != nil {
			opts.Slot = yubikey.PIVSlot(bootstrap.Spec.Envelope.YubiKey.Slot)
			opts.PublicKeyFingerprint = bootstrap.Spec.Envelope.YubiKey.PublicKeyFingerprint
		}
		return yubikey.NewProvider(opts)

	case "tpm":
		opts := tpm.Options{}
		if bootstrap.Spec.Envelope.TPM != nil && bootstrap.Spec.Envelope.TPM.PCRSelection != nil {
			opts.PCRSelection = &tpm.PCRSelection{
				Hash: tpm.HashAlgorithm(bootstrap.Spec.Envelope.TPM.PCRSelection.Hash),
				PCRs: bootstrap.Spec.Envelope.TPM.PCRSelection.PCRs,
			}
		}
		return tpm.NewProvider(opts)

	case "mock":
		return kmsmock.NewProvider(), nil

	default:
		return nil, fmt.Errorf("unknown provider: %s", bootstrap.Spec.Envelope.Provider)
	}
}

// AttestationVerifier verifies identity attestation claims.
// This interface allows dependency injection for testing.
type AttestationVerifier interface {
	VerifyAttestation(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap) (string, error)
}

// DefaultAttestationVerifier performs real attestation verification
type DefaultAttestationVerifier struct{}

// VerifyAttestation implements AttestationVerifier for production use
func (v *DefaultAttestationVerifier) VerifyAttestation(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap) (string, error) {
	// If no attestation is configured, skip verification
	if bootstrap.Spec.Attestation == nil {
		return "", nil
	}

	attestation := bootstrap.Spec.Attestation

	// AWS IRSA
	if attestation.AWSIRSA != nil {
		verifier, err := awsidentity.NewVerifier(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to create AWS IRSA verifier: %w", err)
		}

		policy := &awsidentity.Policy{
			RoleArn: attestation.AWSIRSA.RoleArn,
		}

		claims, err := verifier.Verify(ctx, policy)
		if err != nil {
			return "", fmt.Errorf("AWS IRSA verification failed: %w", err)
		}

		return claims.RoleArn, nil
	}

	// GCP Workload Identity
	if attestation.GCPWorkloadIdentity != nil {
		verifier := gcpidentity.NewVerifier()

		policy := &gcpidentity.Policy{
			ServiceAccount: attestation.GCPWorkloadIdentity.ServiceAccount,
		}

		claims, err := verifier.Verify(ctx, policy)
		if err != nil {
			return "", fmt.Errorf("GCP Workload Identity verification failed: %w", err)
		}

		return claims.ServiceAccount, nil
	}

	// GitHub Actions OIDC
	if attestation.GitHubActions != nil {
		verifier := github.NewVerifier()

		// Read the OIDC token from environment variable
		token := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		if token == "" {
			return "", fmt.Errorf("GitHub Actions OIDC token not found in environment")
		}

		policy := &github.Policy{
			Audience:           attestation.GitHubActions.Audience,
			Repository:         attestation.GitHubActions.Repository,
			RepositoryOwner:    attestation.GitHubActions.RepositoryOwner,
			Workflow:           attestation.GitHubActions.Workflow,
			Environment:        attestation.GitHubActions.Environment,
			Ref:                attestation.GitHubActions.Ref,
			RefPatterns:        attestation.GitHubActions.RefPatterns,
			AllowedActors:      attestation.GitHubActions.AllowedActors,
			RequireEnvironment: attestation.GitHubActions.RequireEnvironment,
		}

		claims, err := verifier.VerifyToken(ctx, token, policy)
		if err != nil {
			return "", fmt.Errorf("GitHub Actions OIDC verification failed: %w", err)
		}

		return claims.Subject, nil
	}

	// Generic OIDC (if needed in the future)
	if attestation.OIDC != nil {
		return "", fmt.Errorf("generic OIDC attestation not yet implemented")
	}

	return "", fmt.Errorf("no valid attestation configuration found")
}

// GenesisBootstrapReconciler reconciles a GenesisBootstrap object
type GenesisBootstrapReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// ProviderFactory creates KMS providers. If nil, uses DefaultProviderFactory.
	ProviderFactory ProviderFactory

	// AttestationVerifier verifies identity attestation. If nil, uses DefaultAttestationVerifier.
	AttestationVerifier AttestationVerifier

	// genesisHandle holds the bridge handle for the genesis-core Rust state machine.
	// It tracks the crypto lifecycle (Uninitialized -> Initialized -> Active).
	// Must be freed with Free() when the reconciler is shut down.
	genesisHandle *bridge.Handle
}

// getProviderFactory returns the configured provider factory or the default
func (r *GenesisBootstrapReconciler) getProviderFactory() ProviderFactory {
	if r.ProviderFactory != nil {
		return r.ProviderFactory
	}
	return &DefaultProviderFactory{}
}

// getAttestationVerifier returns the configured attestation verifier or the default
func (r *GenesisBootstrapReconciler) getAttestationVerifier() AttestationVerifier {
	if r.AttestationVerifier != nil {
		return r.AttestationVerifier
	}
	return &DefaultAttestationVerifier{}
}

// +kubebuilder:rbac:groups=genesis.io,resources=genesisbootstraps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=genesis.io,resources=genesisbootstraps/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=genesis.io,resources=genesisbootstraps/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile handles the reconciliation loop for GenesisBootstrap resources
func (r *GenesisBootstrapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Reconciling GenesisBootstrap")

	// Fetch the GenesisBootstrap instance
	bootstrap := &genesisv1alpha1.GenesisBootstrap{}
	if err := r.Get(ctx, req.NamespacedName, bootstrap); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("GenesisBootstrap not found, likely deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get GenesisBootstrap")
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !bootstrap.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, bootstrap)
	}

	// Add finalizer if not present
	if !controllerutil.ContainsFinalizer(bootstrap, finalizerName) {
		controllerutil.AddFinalizer(bootstrap, finalizerName)
		if err := r.Update(ctx, bootstrap); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Create KMS provider
	provider, err := r.createProvider(ctx, bootstrap)
	if err != nil {
		logger.Error(err, "Failed to create KMS provider")
		r.setCondition(bootstrap, genesisv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			genesisv1alpha1.ReasonProviderNotSupported, err.Error())
		if statusErr := r.Status().Update(ctx, bootstrap); statusErr != nil {
			logger.Error(statusErr, "Failed to update status")
		}
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}

	// Verify attestation if required
	identity, err := r.verifyAttestation(ctx, bootstrap)
	if err != nil {
		logger.Error(err, "Attestation verification failed")
		r.setCondition(bootstrap, genesisv1alpha1.ConditionTypeAttestationValid, metav1.ConditionFalse,
			genesisv1alpha1.ReasonAttestationFailed, err.Error())
		if statusErr := r.Status().Update(ctx, bootstrap); statusErr != nil {
			logger.Error(statusErr, "Failed to update status")
		}
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}

	// Decrypt the envelope
	privateKey, err := r.decryptEnvelope(ctx, provider, bootstrap)
	if err != nil {
		logger.Error(err, "Failed to decrypt envelope")
		r.setCondition(bootstrap, genesisv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			genesisv1alpha1.ReasonDecryptionFailed, err.Error())
		if statusErr := r.Status().Update(ctx, bootstrap); statusErr != nil {
			logger.Error(statusErr, "Failed to update status")
		}
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}

	// Create or update the secret
	if err := r.ensureSecret(ctx, bootstrap, privateKey); err != nil {
		logger.Error(err, "Failed to ensure secret")
		r.setCondition(bootstrap, genesisv1alpha1.ConditionTypeSecretCreated, metav1.ConditionFalse,
			genesisv1alpha1.ReasonSecretCreationFailed, err.Error())
		if statusErr := r.Status().Update(ctx, bootstrap); statusErr != nil {
			logger.Error(statusErr, "Failed to update status")
		}
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}

	// Update status
	r.updateSuccessStatus(bootstrap, provider, privateKey, identity)
	if err := r.Status().Update(ctx, bootstrap); err != nil {
		logger.Error(err, "Failed to update status")
		return ctrl.Result{}, err
	}

	logger.Info("Successfully reconciled GenesisBootstrap",
		"secretName", bootstrap.Spec.Output.SecretName,
		"secretNamespace", bootstrap.Spec.Output.SecretNamespace)

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *GenesisBootstrapReconciler) handleDeletion(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if controllerutil.ContainsFinalizer(bootstrap, finalizerName) {
		// Free the bridge handle if it exists
		if r.genesisHandle != nil {
			r.genesisHandle.Free()
			r.genesisHandle = nil
		}

		// Clean up the secret if we created it
		secret := &corev1.Secret{}
		secretKey := types.NamespacedName{
			Name:      bootstrap.Spec.Output.SecretName,
			Namespace: bootstrap.Spec.Output.SecretNamespace,
		}
		if err := r.Get(ctx, secretKey, secret); err == nil {
			// Check if we own this secret
			if isOwnedBy(secret, bootstrap) {
				logger.Info("Deleting managed secret", "name", secretKey.Name, "namespace", secretKey.Namespace)
				if err := r.Delete(ctx, secret); err != nil && !errors.IsNotFound(err) {
					return ctrl.Result{}, err
				}
			}
		}

		// Remove finalizer
		controllerutil.RemoveFinalizer(bootstrap, finalizerName)
		if err := r.Update(ctx, bootstrap); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *GenesisBootstrapReconciler) createProvider(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap) (kms.Provider, error) {
	return r.getProviderFactory().CreateProvider(ctx, bootstrap)
}

func (r *GenesisBootstrapReconciler) verifyAttestation(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap) (string, error) {
	return r.getAttestationVerifier().VerifyAttestation(ctx, bootstrap)
}

// decryptEnvelope decrypts the KMS-encrypted envelope and validates the key.
//
// The bridge (genesis-core Rust) is used for state tracking and key validation
// via Load + Verify. The Go KMS provider performs the actual KMS decryption so
// the private key can be written to K8s secrets by the Go client.
//
// TODO(WF-4): When bridge.InjectSecret uses a real K8s SecretInjector instead
// of MockSecretInjector, migrate to bridge.BeginBootstrap + bridge.InjectSecret
// so the private key never crosses the FFI boundary into Go memory.
func (r *GenesisBootstrapReconciler) decryptEnvelope(ctx context.Context, provider kms.Provider, bootstrap *genesisv1alpha1.GenesisBootstrap) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(bootstrap.Spec.Envelope.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// --- Bridge: load envelope into Rust state machine for validation ---
	handle, err := bridge.New(`{"provider_type":"mock","provider_config":{}}`)
	if err != nil {
		return "", fmt.Errorf("failed to create genesis handle: %w", err)
	}
	// Track the handle on the reconciler for state reporting
	if r.genesisHandle != nil {
		r.genesisHandle.Free()
	}
	r.genesisHandle = handle

	if err := handle.Load(bootstrap.Spec.Envelope.PublicKey, ciphertext); err != nil {
		return "", fmt.Errorf("failed to load envelope into bridge: %w", err)
	}

	// --- Go KMS: decrypt the envelope to extract the private key ---
	// The Go KMS provider is used because bridge.InjectSecret currently uses
	// MockSecretInjector and cannot write to real K8s secrets.
	plaintext, err := provider.Decrypt(ctx, ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt envelope: %w", err)
	}

	privateKey := string(plaintext)

	// Validate the decrypted key is a valid age private key
	if !strings.HasPrefix(privateKey, "AGE-SECRET-KEY-1") {
		return "", fmt.Errorf("decrypted content is not a valid age private key")
	}

	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		return "", fmt.Errorf("decrypted key is invalid: %w", err)
	}

	// Verify public key matches if specified
	derivedPubKey := identity.Recipient().String()
	if bootstrap.Spec.Envelope.PublicKey != "" && derivedPubKey != bootstrap.Spec.Envelope.PublicKey {
		return "", fmt.Errorf("public key mismatch: expected %s, got %s",
			bootstrap.Spec.Envelope.PublicKey, derivedPubKey)
	}

	return privateKey, nil
}

func (r *GenesisBootstrapReconciler) ensureSecret(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap, privateKey string) error {
	logger := log.FromContext(ctx)

	// Ensure the target namespace exists
	ns := &corev1.Namespace{}
	if err := r.Get(ctx, types.NamespacedName{Name: bootstrap.Spec.Output.SecretNamespace}, ns); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Errorf("target namespace %s does not exist", bootstrap.Spec.Output.SecretNamespace)
		}
		return err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bootstrap.Spec.Output.SecretName,
			Namespace: bootstrap.Spec.Output.SecretNamespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		// Set labels
		if secret.Labels == nil {
			secret.Labels = make(map[string]string)
		}
		secret.Labels["app.kubernetes.io/managed-by"] = "genesis-operator"
		secret.Labels["genesis.io/bootstrap"] = bootstrap.Name

		// Set annotations
		if secret.Annotations == nil {
			secret.Annotations = make(map[string]string)
		}
		secret.Annotations["genesis.io/source-namespace"] = bootstrap.Namespace
		secret.Annotations["genesis.io/source-name"] = bootstrap.Name

		// Set data
		secret.Type = corev1.SecretTypeOpaque
		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}
		secret.Data[bootstrap.Spec.Output.SecretKey] = []byte(privateKey)

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to create/update secret: %w", err)
	}

	logger.Info("Secret operation completed", "operation", op,
		"name", secret.Name, "namespace", secret.Namespace)

	// Handle additional namespaces
	for _, ns := range bootstrap.Spec.Output.AdditionalNamespaces {
		if err := r.ensureSecretInNamespace(ctx, bootstrap, privateKey, ns); err != nil {
			logger.Error(err, "Failed to create secret in additional namespace", "namespace", ns)
		}
	}

	return nil
}

func (r *GenesisBootstrapReconciler) ensureSecretInNamespace(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap, privateKey string, namespace string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bootstrap.Spec.Output.SecretName,
			Namespace: namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if secret.Labels == nil {
			secret.Labels = make(map[string]string)
		}
		secret.Labels["app.kubernetes.io/managed-by"] = "genesis-operator"
		secret.Labels["genesis.io/bootstrap"] = bootstrap.Name

		if secret.Annotations == nil {
			secret.Annotations = make(map[string]string)
		}
		secret.Annotations["genesis.io/source-namespace"] = bootstrap.Namespace
		secret.Annotations["genesis.io/source-name"] = bootstrap.Name

		secret.Type = corev1.SecretTypeOpaque
		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}
		secret.Data[bootstrap.Spec.Output.SecretKey] = []byte(privateKey)

		return nil
	})

	return err
}

func (r *GenesisBootstrapReconciler) updateSuccessStatus(bootstrap *genesisv1alpha1.GenesisBootstrap, provider kms.Provider, privateKey string, identity string) {
	now := metav1.Now()

	// Derive public key from private key using age library directly.
	// This replaces the former crypto.ParseAgeKeypair call.
	var publicKey string
	if ident, err := age.ParseX25519Identity(privateKey); err == nil {
		publicKey = ident.Recipient().String()
	}

	// Set bridge state on status if handle is available
	if r.genesisHandle != nil {
		bootstrap.Status.State = r.genesisHandle.State().String()
	}

	// Set Ready condition
	r.setCondition(bootstrap, genesisv1alpha1.ConditionTypeReady, metav1.ConditionTrue,
		genesisv1alpha1.ReasonDecryptionKeyProvisioned,
		fmt.Sprintf("Age decryption key successfully provisioned to %s/%s",
			bootstrap.Spec.Output.SecretNamespace, bootstrap.Spec.Output.SecretName))

	// Set SecretCreated condition
	r.setCondition(bootstrap, genesisv1alpha1.ConditionTypeSecretCreated, metav1.ConditionTrue,
		genesisv1alpha1.ReasonSecretCreated,
		fmt.Sprintf("Secret created in namespace %s", bootstrap.Spec.Output.SecretNamespace))

	// Set AttestationValid condition if attestation was configured
	if bootstrap.Spec.Attestation != nil {
		r.setCondition(bootstrap, genesisv1alpha1.ConditionTypeAttestationValid, metav1.ConditionTrue,
			genesisv1alpha1.ReasonAttestationSucceeded,
			fmt.Sprintf("Identity attestation succeeded: %s", identity))
	}

	// Update attestation status
	bootstrap.Status.LastAttestation = &genesisv1alpha1.AttestationStatus{
		Time:     now,
		Provider: string(provider.Name()),
		Identity: identity,
	}

	// Update key metadata
	bootstrap.Status.KeyMetadata = &genesisv1alpha1.KeyMetadata{
		PublicKey: publicKey,
		Algorithm: "X25519",
	}

	bootstrap.Status.ObservedGeneration = bootstrap.Generation
}

func (r *GenesisBootstrapReconciler) setCondition(bootstrap *genesisv1alpha1.GenesisBootstrap, condType string, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()

	// Find existing condition
	for i, c := range bootstrap.Status.Conditions {
		if c.Type == condType {
			if c.Status != status || c.Reason != reason || c.Message != message {
				bootstrap.Status.Conditions[i] = metav1.Condition{
					Type:               condType,
					Status:             status,
					LastTransitionTime: now,
					Reason:             reason,
					Message:            message,
				}
			}
			return
		}
	}

	// Add new condition
	bootstrap.Status.Conditions = append(bootstrap.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	})
}

func isOwnedBy(secret *corev1.Secret, bootstrap *genesisv1alpha1.GenesisBootstrap) bool {
	if secret.Labels == nil {
		return false
	}
	return secret.Labels["genesis.io/bootstrap"] == bootstrap.Name
}

// SetupWithManager sets up the controller with the Manager
func (r *GenesisBootstrapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&genesisv1alpha1.GenesisBootstrap{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
