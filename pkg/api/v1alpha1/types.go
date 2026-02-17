package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Provider",type="string",JSONPath=".spec.envelope.provider"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GenesisBootstrap is the Schema for the genesisbootstraps API
type GenesisBootstrap struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GenesisBootstrapSpec   `json:"spec,omitempty"`
	Status GenesisBootstrapStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GenesisBootstrapList contains a list of GenesisBootstrap
type GenesisBootstrapList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GenesisBootstrap `json:"items"`
}

// GenesisBootstrapSpec defines the desired state of GenesisBootstrap
type GenesisBootstrapSpec struct {
	// Envelope contains the encrypted master key configuration
	Envelope EnvelopeSpec `json:"envelope"`

	// Attestation contains identity attestation requirements (optional)
	// +optional
	Attestation *AttestationSpec `json:"attestation,omitempty"`

	// Output defines where to create the decryption secret
	Output OutputSpec `json:"output"`
}

// EnvelopeSpec defines the envelope-encrypted master key configuration
type EnvelopeSpec struct {
	// Provider specifies the KMS provider type
	// +kubebuilder:validation:Enum=aws-kms;gcp-kms;azure-keyvault;oci-vault;yubikey;tpm
	Provider string `json:"provider"`

	// AWSKms contains AWS KMS specific configuration
	// +optional
	AWSKms *AWSKmsSpec `json:"awsKms,omitempty"`

	// GCPKms contains GCP KMS specific configuration
	// +optional
	GCPKms *GCPKmsSpec `json:"gcpKms,omitempty"`

	// AzureKeyVault contains Azure Key Vault specific configuration
	// +optional
	AzureKeyVault *AzureKeyVaultSpec `json:"azureKeyVault,omitempty"`

	// OCIVault contains OCI Vault specific configuration
	// +optional
	OCIVault *OCIVaultSpec `json:"ociVault,omitempty"`

	// YubiKey contains YubiKey PIV specific configuration
	// +optional
	YubiKey *YubiKeySpec `json:"yubikey,omitempty"`

	// TPM contains TPM 2.0 specific configuration
	// +optional
	TPM *TPMSpec `json:"tpm,omitempty"`

	// Ciphertext is the base64-encoded encrypted age private key
	Ciphertext string `json:"ciphertext"`

	// PublicKey is the age public key (for reference, not secret)
	// +optional
	PublicKey string `json:"publicKey,omitempty"`
}

// AWSKmsSpec defines AWS KMS configuration
type AWSKmsSpec struct {
	// KeyArn is the ARN of the AWS KMS key
	KeyArn string `json:"keyArn"`

	// Region is the AWS region (optional, extracted from ARN if not specified)
	// +optional
	Region string `json:"region,omitempty"`
}

// GCPKmsSpec defines GCP KMS configuration
type GCPKmsSpec struct {
	// KeyName is the full resource name of the GCP KMS key
	KeyName string `json:"keyName"`
}

// AzureKeyVaultSpec defines Azure Key Vault configuration
type AzureKeyVaultSpec struct {
	// VaultURL is the URL of the Azure Key Vault
	VaultUrl string `json:"vaultUrl"`

	// KeyName is the name of the key in the vault
	KeyName string `json:"keyName"`

	// KeyVersion is the specific version of the key (optional, uses latest if empty)
	// +optional
	KeyVersion string `json:"keyVersion,omitempty"`
}

// OCIVaultSpec defines OCI Vault configuration
type OCIVaultSpec struct {
	// KeyOCID is the OCID of the master encryption key
	KeyOCID string `json:"keyOcid"`

	// CryptoEndpoint is the cryptographic endpoint for the vault
	CryptoEndpoint string `json:"cryptoEndpoint"`
}

// YubiKeySpec defines YubiKey PIV configuration
type YubiKeySpec struct {
	// Slot is the PIV slot to use (e.g., "9a")
	// +kubebuilder:default="9a"
	Slot string `json:"slot,omitempty"`

	// PublicKeyFingerprint is the SHA256 fingerprint of the public key
	PublicKeyFingerprint string `json:"publicKeyFingerprint,omitempty"`
}

// TPMSpec defines TPM 2.0 configuration
type TPMSpec struct {
	// PCRSelection defines which PCRs to use for sealing
	PCRSelection *PCRSelection `json:"pcrSelection,omitempty"`
}

// PCRSelection defines TPM PCR selection
type PCRSelection struct {
	// Hash is the hash algorithm (e.g., "sha256")
	// +kubebuilder:default="sha256"
	Hash string `json:"hash,omitempty"`

	// PCRs is the list of PCR indices to use
	PCRs []int `json:"pcrs,omitempty"`
}

// AttestationSpec defines identity attestation requirements
type AttestationSpec struct {
	// OIDC contains OIDC-based identity configuration
	// +optional
	OIDC *OIDCSpec `json:"oidc,omitempty"`

	// AWSIRSA contains AWS IRSA specific configuration
	// +optional
	AWSIRSA *AWSIRSASpec `json:"awsIrsa,omitempty"`

	// GCPWorkloadIdentity contains GCP Workload Identity configuration
	// +optional
	GCPWorkloadIdentity *GCPWorkloadIdentitySpec `json:"gcpWorkloadIdentity,omitempty"`

	// GitHubActions contains GitHub Actions OIDC configuration
	// +optional
	GitHubActions *GitHubActionsSpec `json:"githubActions,omitempty"`
}

// OIDCSpec defines OIDC identity configuration
type OIDCSpec struct {
	// Issuer is the OIDC issuer URL
	Issuer string `json:"issuer"`

	// Audience is the expected audience claim
	Audience string `json:"audience"`

	// Subject is the expected subject claim
	Subject string `json:"subject"`
}

// AWSIRSASpec defines AWS IRSA configuration
type AWSIRSASpec struct {
	// RoleArn is the ARN of the IAM role to assume
	RoleArn string `json:"roleArn"`
}

// GCPWorkloadIdentitySpec defines GCP Workload Identity configuration
type GCPWorkloadIdentitySpec struct {
	// ServiceAccount is the GCP service account email
	ServiceAccount string `json:"serviceAccount"`
}

// GitHubActionsSpec defines GitHub Actions OIDC configuration
type GitHubActionsSpec struct {
	// Audience is the expected audience claim (defaults to genesis-operator)
	// +optional
	Audience string `json:"audience,omitempty"`

	// Repository restricts to a specific repository (e.g., "owner/repo")
	// +optional
	Repository string `json:"repository,omitempty"`

	// RepositoryOwner restricts to repositories owned by this user/org
	// +optional
	RepositoryOwner string `json:"repositoryOwner,omitempty"`

	// Workflow restricts to a specific workflow file
	// +optional
	Workflow string `json:"workflow,omitempty"`

	// Environment restricts to a specific GitHub environment
	// +optional
	Environment string `json:"environment,omitempty"`

	// Ref restricts to a specific ref (e.g., "refs/heads/main")
	// +optional
	Ref string `json:"ref,omitempty"`

	// RefPatterns is a list of ref patterns to allow (glob-style)
	// +optional
	RefPatterns []string `json:"refPatterns,omitempty"`

	// AllowedActors restricts which actors can authenticate
	// +optional
	AllowedActors []string `json:"allowedActors,omitempty"`

	// RequireEnvironment requires the environment claim to be present
	// +optional
	RequireEnvironment bool `json:"requireEnvironment,omitempty"`
}

// OutputSpec defines where to create the decryption secret
type OutputSpec struct {
	// SecretName is the name of the secret to create
	// +kubebuilder:default="sops-age"
	SecretName string `json:"secretName"`

	// SecretNamespace is the namespace for the secret
	// +kubebuilder:default="flux-system"
	SecretNamespace string `json:"secretNamespace"`

	// SecretKey is the key within the secret for the age private key
	// +kubebuilder:default="age.agekey"
	SecretKey string `json:"secretKey"`

	// AdditionalNamespaces lists additional namespaces to copy the secret to
	// +optional
	AdditionalNamespaces []string `json:"additionalNamespaces,omitempty"`
}

// GenesisBootstrapStatus defines the observed state of GenesisBootstrap
type GenesisBootstrapStatus struct {
	// Conditions represent the latest available observations of the resource's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastAttestation contains information about the last successful attestation
	// +optional
	LastAttestation *AttestationStatus `json:"lastAttestation,omitempty"`

	// KeyMetadata contains non-sensitive metadata about the key
	// +optional
	KeyMetadata *KeyMetadata `json:"keyMetadata,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// AttestationStatus contains information about the last successful attestation
type AttestationStatus struct {
	// Time is when the attestation occurred
	Time metav1.Time `json:"time"`

	// Provider is the KMS provider used
	Provider string `json:"provider"`

	// Identity is the identity that was attested
	Identity string `json:"identity,omitempty"`
}

// KeyMetadata contains non-sensitive metadata about the key
type KeyMetadata struct {
	// PublicKey is the age public key
	PublicKey string `json:"publicKey"`

	// CreatedAt is when the key was created
	CreatedAt metav1.Time `json:"createdAt,omitempty"`

	// Algorithm is the encryption algorithm (e.g., "X25519")
	// +kubebuilder:default="X25519"
	Algorithm string `json:"algorithm,omitempty"`
}

// Condition types for GenesisBootstrap
const (
	// ConditionTypeReady indicates the bootstrap is ready
	ConditionTypeReady = "Ready"

	// ConditionTypeSecretCreated indicates the secret was created
	ConditionTypeSecretCreated = "SecretCreated"

	// ConditionTypeAttestationValid indicates attestation succeeded
	ConditionTypeAttestationValid = "AttestationValid"
)

// Condition reasons
const (
	ReasonDecryptionKeyProvisioned = "DecryptionKeyProvisioned"
	ReasonDecryptionFailed         = "DecryptionFailed"
	ReasonSecretCreated            = "SecretCreated"
	ReasonSecretCreationFailed     = "SecretCreationFailed"
	ReasonAttestationSucceeded     = "AttestationSucceeded"
	ReasonAttestationFailed        = "AttestationFailed"
	ReasonProviderNotSupported     = "ProviderNotSupported"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Source",type="string",JSONPath=".spec.source.name"
// +kubebuilder:printcolumn:name="Interval",type="string",JSONPath=".spec.schedule.interval"
// +kubebuilder:printcolumn:name="LastRotation",type="date",JSONPath=".status.lastRotation.time"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// GenesisRotationPolicy is the Schema for the genesisrotationpolicies API
type GenesisRotationPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GenesisRotationPolicySpec   `json:"spec,omitempty"`
	Status GenesisRotationPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GenesisRotationPolicyList contains a list of GenesisRotationPolicy
type GenesisRotationPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GenesisRotationPolicy `json:"items"`
}

// GenesisRotationPolicySpec defines the desired state of GenesisRotationPolicy
type GenesisRotationPolicySpec struct {
	// Source specifies the secret to rotate
	Source RotationSourceSpec `json:"source"`

	// Schedule defines when rotation should occur
	Schedule RotationScheduleSpec `json:"schedule"`

	// Strategy defines how rotation should be performed
	// +optional
	Strategy *RotationStrategySpec `json:"strategy,omitempty"`

	// Notify defines notification channels for rotation events
	// +optional
	Notify []NotificationSpec `json:"notify,omitempty"`

	// Suspend allows temporarily disabling rotation
	// +optional
	Suspend bool `json:"suspend,omitempty"`
}

// RotationSourceSpec defines the source secret to rotate
type RotationSourceSpec struct {
	// Kind is the Kubernetes resource kind (typically "Secret")
	// +kubebuilder:default="Secret"
	Kind string `json:"kind,omitempty"`

	// Name is the name of the resource
	Name string `json:"name"`

	// Namespace is the namespace of the resource
	Namespace string `json:"namespace"`
}

// RotationScheduleSpec defines when rotation should occur
type RotationScheduleSpec struct {
	// Interval is the duration between rotations (e.g., "720h" for 30 days)
	// +kubebuilder:validation:Pattern="^[0-9]+(h|m|s)$"
	Interval string `json:"interval"`
}

// RotationStrategySpec defines how rotation should be performed
type RotationStrategySpec struct {
	// Type is the rotation strategy type
	// +kubebuilder:validation:Enum=BlueGreen;Rolling;Immediate
	// +kubebuilder:default="BlueGreen"
	Type string `json:"type,omitempty"`

	// OverlapPeriod is how long old and new secrets coexist (for BlueGreen)
	// +optional
	OverlapPeriod string `json:"overlapPeriod,omitempty"`
}

// NotificationSpec defines a notification channel
type NotificationSpec struct {
	// Type is the notification type
	// +kubebuilder:validation:Enum=Event;Slack;Webhook;PagerDuty
	Type string `json:"type"`

	// Channel is the target channel (for Slack)
	// +optional
	Channel string `json:"channel,omitempty"`

	// WebhookSecretRef references a secret containing the webhook URL
	// +optional
	WebhookSecretRef *SecretKeySelector `json:"webhookSecretRef,omitempty"`
}

// SecretKeySelector selects a key of a Secret
type SecretKeySelector struct {
	// Name is the name of the secret
	Name string `json:"name"`

	// Key is the key within the secret
	Key string `json:"key"`

	// Namespace is the namespace of the secret (defaults to policy namespace)
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// GenesisRotationPolicyStatus defines the observed state of GenesisRotationPolicy
type GenesisRotationPolicyStatus struct {
	// Conditions represent the latest available observations of the resource's state
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastRotation contains information about the last successful rotation
	// +optional
	LastRotation *RotationStatus `json:"lastRotation,omitempty"`

	// NextRotation is when the next rotation is scheduled
	// +optional
	NextRotation *metav1.Time `json:"nextRotation,omitempty"`

	// RotationCount is the total number of successful rotations
	// +optional
	RotationCount int64 `json:"rotationCount,omitempty"`

	// ObservedGeneration is the last observed generation
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// RotationStatus contains information about a rotation event
type RotationStatus struct {
	// Time is when the rotation occurred
	Time metav1.Time `json:"time"`

	// OldVersion is the version of the old secret
	OldVersion string `json:"oldVersion,omitempty"`

	// NewVersion is the version of the new secret
	NewVersion string `json:"newVersion,omitempty"`

	// Success indicates whether the rotation was successful
	Success bool `json:"success"`

	// Message provides additional details about the rotation
	Message string `json:"message,omitempty"`
}

// Condition types for GenesisRotationPolicy
const (
	// ConditionTypeRotationReady indicates the policy is ready to rotate
	ConditionTypeRotationReady = "Ready"

	// ConditionTypeRotationDue indicates a rotation is due
	ConditionTypeRotationDue = "RotationDue"

	// ConditionTypeRotationInProgress indicates a rotation is in progress
	ConditionTypeRotationInProgress = "RotationInProgress"
)

// Condition reasons for rotation
const (
	ReasonRotationScheduled  = "RotationScheduled"
	ReasonRotationInProgress = "RotationInProgress"
	ReasonRotationSucceeded  = "RotationSucceeded"
	ReasonRotationFailed     = "RotationFailed"
	ReasonRotationSuspended  = "RotationSuspended"
)

func init() {
	SchemeBuilder.Register(&GenesisBootstrap{}, &GenesisBootstrapList{})
	SchemeBuilder.Register(&GenesisRotationPolicy{}, &GenesisRotationPolicyList{})
}
