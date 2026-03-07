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

// BootstrapInjector abstracts the decrypt + secret injection flow.
// Production uses the Rust bridge (BridgeBootstrapInjector); tests use the
// legacy Go KMS path (LegacyBootstrapInjector).
type BootstrapInjector interface {
	// Bootstrap decrypts the envelope and injects the secret into Kubernetes.
	// Returns the public key for status reporting and a bridge handle for state tracking.
	Bootstrap(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap) (publicKey string, handle *bridge.Handle, err error)
}

// BridgeBootstrapInjector implements BootstrapInjector using the Rust bridge.
// Key material never enters Go memory — decryption and secret injection happen
// entirely in Rust via the genesis-core FFI.
type BridgeBootstrapInjector struct{}

// Bootstrap implements BootstrapInjector via the Rust bridge path:
// BuildKmsConfigJSON -> New -> Load -> BeginBootstrap -> InjectSecret.
func (b *BridgeBootstrapInjector) Bootstrap(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap) (string, *bridge.Handle, error) {
	// 1. Build KMS config JSON from CRD spec
	kmsConfigJSON, err := bridge.BuildKmsConfigJSON(&bootstrap.Spec.Envelope)
	if err != nil {
		return "", nil, fmt.Errorf("failed to build KMS config: %w", err)
	}

	// 2. Create bridge handle with real KMS provider
	handle, err := bridge.New(kmsConfigJSON)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create genesis handle: %w", err)
	}

	// 3. Decode ciphertext and load envelope
	ciphertext, err := base64.StdEncoding.DecodeString(bootstrap.Spec.Envelope.Ciphertext)
	if err != nil {
		handle.Free()
		return "", nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	if bootstrap.Spec.Envelope.PublicKey == "" {
		handle.Free()
		return "", nil, fmt.Errorf("public key is required for bridge bootstrap")
	}

	if err := handle.Load(bootstrap.Spec.Envelope.PublicKey, ciphertext); err != nil {
		handle.Free()
		return "", nil, fmt.Errorf("failed to load envelope: %w", err)
	}

	// 4. Begin bootstrap — decrypt in Rust memory
	if err := handle.BeginBootstrap(kmsConfigJSON); err != nil {
		handle.Free()
		return "", nil, fmt.Errorf("failed to begin bootstrap: %w", err)
	}

	// 5. Build injection targets (primary + additional namespaces)
	targets := []bridge.InjectTarget{
		{
			Name:               bootstrap.Spec.Output.SecretName,
			Namespace:          bootstrap.Spec.Output.SecretNamespace,
			Key:                bootstrap.Spec.Output.SecretKey,
			BootstrapName:      bootstrap.Name,
			BootstrapNamespace: bootstrap.Namespace,
		},
	}
	for _, ns := range bootstrap.Spec.Output.AdditionalNamespaces {
		targets = append(targets, bridge.InjectTarget{
			Name:               bootstrap.Spec.Output.SecretName,
			Namespace:          ns,
			Key:                bootstrap.Spec.Output.SecretKey,
			BootstrapName:      bootstrap.Name,
			BootstrapNamespace: bootstrap.Namespace,
		})
	}

	// 6. Inject secrets via Rust ureq HTTP (all targets in one FFI call)
	if err := handle.InjectSecrets(targets); err != nil {
		handle.Free()
		return "", nil, fmt.Errorf("failed to inject secrets: %w", err)
	}

	return bootstrap.Spec.Envelope.PublicKey, handle, nil
}

// LegacyBootstrapInjector implements BootstrapInjector using the Go KMS
// decrypt path and controller-runtime client for K8s secret creation.
// This exists for test compatibility (fake K8s client). Production code
// uses BridgeBootstrapInjector which handles AdditionalNamespaces natively.
type LegacyBootstrapInjector struct {
	Client          client.Client
	ProviderFactory ProviderFactory
}

// Bootstrap implements BootstrapInjector via the legacy Go path:
// Go KMS decrypt -> age key validation -> controller-runtime secret creation.
func (l *LegacyBootstrapInjector) Bootstrap(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap) (string, *bridge.Handle, error) {
	// 1. Create Go KMS provider
	provider, err := l.ProviderFactory.CreateProvider(ctx, bootstrap)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create KMS provider: %w", err)
	}

	// 2. Decode ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(bootstrap.Spec.Envelope.Ciphertext)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// 3. Create bridge handle (mock) for state tracking
	handle, err := bridge.New(`{"provider_type":"mock","provider_config":{}}`)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create genesis handle: %w", err)
	}

	if err := handle.Load(bootstrap.Spec.Envelope.PublicKey, ciphertext); err != nil {
		handle.Free()
		return "", nil, fmt.Errorf("failed to load envelope into bridge: %w", err)
	}

	// 4. Go KMS: decrypt the envelope to extract the private key
	plaintext, err := provider.Decrypt(ctx, ciphertext)
	if err != nil {
		handle.Free()
		return "", nil, fmt.Errorf("failed to decrypt envelope: %w", err)
	}

	privateKey := string(plaintext) // legacy-go-path: test-only

	// 5. Validate the decrypted key is a valid age private key
	if !strings.HasPrefix(privateKey, "AGE-SECRET-KEY-1") { // legacy-go-path: test-only
		handle.Free()
		return "", nil, fmt.Errorf("decrypted content is not a valid age private key")
	}

	identity, err := age.ParseX25519Identity(privateKey) // legacy-go-path: test-only
	if err != nil {
		handle.Free()
		return "", nil, fmt.Errorf("decrypted key is invalid: %w", err)
	}

	// 6. Verify public key matches if specified
	derivedPubKey := identity.Recipient().String()
	if bootstrap.Spec.Envelope.PublicKey != "" && derivedPubKey != bootstrap.Spec.Envelope.PublicKey {
		handle.Free()
		return "", nil, fmt.Errorf("public key mismatch: expected %s, got %s",
			bootstrap.Spec.Envelope.PublicKey, derivedPubKey)
	}

	// 7. Create or update the primary secret
	if err := l.ensureSecret(ctx, bootstrap, privateKey); err != nil { // legacy-go-path: test-only
		handle.Free()
		return "", nil, fmt.Errorf("failed to ensure secret: %w", err)
	}

	return derivedPubKey, handle, nil
}

func (l *LegacyBootstrapInjector) ensureSecret(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap, privateKey string) error {
	logger := log.FromContext(ctx)

	// Ensure the target namespace exists
	ns := &corev1.Namespace{}
	if err := l.Client.Get(ctx, types.NamespacedName{Name: bootstrap.Spec.Output.SecretNamespace}, ns); err != nil {
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

	op, err := controllerutil.CreateOrUpdate(ctx, l.Client, secret, func() error {
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
		secret.Data[bootstrap.Spec.Output.SecretKey] = []byte(privateKey) // legacy-go-path: test-only

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to create/update secret: %w", err)
	}

	logger.Info("Secret operation completed", "operation", op,
		"name", secret.Name, "namespace", secret.Namespace)

	// Handle additional namespaces
	for _, ns := range bootstrap.Spec.Output.AdditionalNamespaces {
		if err := l.ensureSecretInNamespace(ctx, bootstrap, privateKey, ns); err != nil { // legacy-go-path: test-only
			logger.Error(err, "Failed to create secret in additional namespace", "namespace", ns)
		}
	}

	return nil
}

func (l *LegacyBootstrapInjector) ensureSecretInNamespace(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap, privateKey string, namespace string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bootstrap.Spec.Output.SecretName,
			Namespace: namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, l.Client, secret, func() error {
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
		secret.Data[bootstrap.Spec.Output.SecretKey] = []byte(privateKey) // legacy-go-path: test-only

		return nil
	})

	return err
}

// GenesisBootstrapReconciler reconciles a GenesisBootstrap object
type GenesisBootstrapReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// ProviderFactory creates KMS providers. If nil, uses DefaultProviderFactory.
	ProviderFactory ProviderFactory

	// AttestationVerifier verifies identity attestation. If nil, uses DefaultAttestationVerifier.
	AttestationVerifier AttestationVerifier

	// BootstrapInjector handles decrypt + inject. If nil, uses BridgeBootstrapInjector
	// (supports both single-target and AdditionalNamespaces via InjectSecrets FFI).
	BootstrapInjector BootstrapInjector

	// genesisHandle holds the bridge handle for the genesis-core Rust state machine.
	// It tracks the crypto lifecycle (Uninitialized -> Initialized -> Active).
	// Must be freed with Free() when the reconciler is shut down.
	genesisHandle *bridge.Handle
}

// getAttestationVerifier returns the configured attestation verifier or the default
func (r *GenesisBootstrapReconciler) getAttestationVerifier() AttestationVerifier {
	if r.AttestationVerifier != nil {
		return r.AttestationVerifier
	}
	return &DefaultAttestationVerifier{}
}

// getBootstrapInjector returns the configured bootstrap injector or the default.
// If explicitly set (e.g. for tests), uses that. Otherwise, uses the Rust bridge
// path which handles both single and multi-target injection (AdditionalNamespaces).
func (r *GenesisBootstrapReconciler) getBootstrapInjector(bootstrap *genesisv1alpha1.GenesisBootstrap) BootstrapInjector {
	if r.BootstrapInjector != nil {
		return r.BootstrapInjector
	}
	return &BridgeBootstrapInjector{}
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

	// Decrypt and inject secret via the BootstrapInjector strategy.
	// BridgeBootstrapInjector (default): key material never enters Go memory.
	// LegacyBootstrapInjector: Go KMS decrypt + controller-runtime client (tests only).
	injector := r.getBootstrapInjector(bootstrap)
	publicKey, handle, err := injector.Bootstrap(ctx, bootstrap)
	if err != nil {
		logger.Error(err, "Failed to bootstrap")
		r.setCondition(bootstrap, genesisv1alpha1.ConditionTypeReady, metav1.ConditionFalse,
			genesisv1alpha1.ReasonDecryptionFailed, err.Error())
		if statusErr := r.Status().Update(ctx, bootstrap); statusErr != nil {
			logger.Error(statusErr, "Failed to update status")
		}
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}

	// Track handle
	if r.genesisHandle != nil {
		r.genesisHandle.Free()
	}
	r.genesisHandle = handle

	// Update status
	r.updateSuccessStatus(bootstrap, publicKey, identity)
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

func (r *GenesisBootstrapReconciler) verifyAttestation(ctx context.Context, bootstrap *genesisv1alpha1.GenesisBootstrap) (string, error) {
	return r.getAttestationVerifier().VerifyAttestation(ctx, bootstrap)
}

func (r *GenesisBootstrapReconciler) updateSuccessStatus(bootstrap *genesisv1alpha1.GenesisBootstrap, publicKey string, identity string) {
	now := metav1.Now()

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
		Provider: bootstrap.Spec.Envelope.Provider,
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
