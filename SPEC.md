# Genesis: Universal GitOps Secrets Bootstrap

## Abstract

Genesis solves the "chicken-and-egg" problem in GitOps secrets management: you need secrets to deploy secrets managers, but your secrets manager is supposed to manage your secrets.

Genesis provides a single, identity-based bootstrap mechanism that works across cloud providers and bare-metal environments, requiring only one manual step (key generation) and then enabling fully automated, declarative secrets lifecycle management.

## Problem Statement

### Current Pain Points

1. **Bootstrap Problem**: Every secrets solution requires manual seeding of initial credentials
2. **Multi-cluster Complexity**: Different keys/controllers per cluster
3. **Rotation is Manual**: No declarative rotation policies
4. **Cloud Lock-in**: Solutions tied to specific cloud KMS
5. **GUI-heavy Setup**: GitHub OIDC federation requires clicking through consoles

### Existing Solutions Comparison

| Tool | Bootstrap | Rotation | Multi-cluster | License |
|------|-----------|----------|---------------|---------|
| SOPS+age | Manual key seeding | Manual | Per-cluster keys | Apache-2.0 |
| Sealed Secrets | Controller keypair in etcd | Key rotation only | Per-cluster controller | Apache-2.0 |
| ESO | Auth to external store | Sync-based | Centralized store | Apache-2.0 |
| Infisical | Operator needs auth | Automatic | Native multi-env | MIT |
| Vault/OpenBao | Unseal ceremony | Dynamic secrets | Complex federation | MPL-2.0/BSL |

## Design Principles

1. **One Secret to Bootstrap All**: Single age keypair, envelope-encrypted with cloud/hardware KMS
2. **Identity Over Credentials**: Clusters prove identity cryptographically, not via pre-shared secrets
3. **GitOps Native**: All configuration lives in git, operator is fully declarative
4. **Cloud Agnostic**: Pluggable identity providers (AWS IRSA, GCP WI, Azure AD, TPM, YubiKey)
5. **Self-Bootstrapping**: Operator needs only cluster RBAC + identity attestation
6. **Minimal Surface Area**: Small, auditable codebase with no unnecessary dependencies

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         INITIALIZATION (One-time, Local)                 │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ $ genesis init --provider aws-kms --key-arn arn:aws:kms:...       │  │
│  │                                                                    │  │
│  │   1. Generate age X25519 keypair (master key)                     │  │
│  │   2. Encrypt master private key with envelope encryption:         │  │
│  │      - AWS KMS: Encrypt API with CMK                              │  │
│  │      - GCP KMS: Encrypt with Cloud KMS key                        │  │
│  │      - Azure: Encrypt with Key Vault key                          │  │
│  │      - YubiKey: PIV slot encryption                               │  │
│  │      - TPM 2.0: Seal to PCR values                                │  │
│  │   3. Output:                                                       │  │
│  │      - genesis-bootstrap.yaml (encrypted, safe for git)           │  │
│  │      - .sops.yaml (age public key config)                         │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         GIT REPOSITORY (Source of Truth)                 │
│                                                                          │
│  clusters/                                                               │
│    └── production/                                                       │
│        ├── genesis/                                                      │
│        │   └── genesis-bootstrap.yaml    # Encrypted master key + policy │
│        ├── flux-system/                                                  │
│        │   └── kustomization.yaml                                        │
│        └── secrets/                                                      │
│            ├── .sops.yaml                # Points to genesis public key  │
│            ├── database-creds.enc.yaml   # SOPS-encrypted secret         │
│            └── api-keys.enc.yaml         # SOPS-encrypted secret         │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    KUBERNETES CLUSTER (Zero-Touch Bootstrap)             │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Step 1: Deploy genesis-operator (Helm/kubectl)                     │ │
│  │         - Only needs: ServiceAccount with cloud identity binding   │ │
│  │         - No secrets passed at deploy time                         │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                    │                                     │
│                                    ▼                                     │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Step 2: Operator watches GenesisBootstrap CRD                      │ │
│  │                                                                     │ │
│  │   a) Read genesis-bootstrap.yaml from GitRepository source         │ │
│  │   b) Prove cluster identity via configured provider:               │ │
│  │      - AWS: IRSA → AssumeRoleWithWebIdentity → KMS:Decrypt         │ │
│  │      - GCP: Workload Identity → cloudkms.decrypt                   │ │
│  │      - Azure: AAD Pod Identity → Key Vault unwrap                  │ │
│  │      - Bare metal: TPM attestation or YubiKey challenge            │ │
│  │   c) Decrypt envelope → obtain age private key                     │ │
│  │   d) Create Kubernetes Secret: genesis-age-key in flux-system      │ │
│  │   e) Emit event: GenesisBootstrapReady                             │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                    │                                     │
│                                    ▼                                     │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Step 3: Flux reconciles with decryption enabled                    │ │
│  │                                                                     │ │
│  │   - Kustomization references decryption secret                     │ │
│  │   - SOPS-encrypted secrets are decrypted and applied               │ │
│  │   - All subsequent secrets managed via GitOps                      │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## API Specification

### Custom Resource Definitions

#### GenesisBootstrap

```yaml
apiVersion: genesis.io/v1alpha1
kind: GenesisBootstrap
metadata:
  name: cluster-secrets
  namespace: genesis-system
spec:
  # Envelope-encrypted master key
  envelope:
    # Provider-specific encryption configuration
    provider: aws-kms | gcp-kms | azure-keyvault | yubikey | tpm
    
    # AWS KMS specific
    awsKms:
      keyArn: arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012
      region: us-west-2
    
    # GCP KMS specific  
    gcpKms:
      keyName: projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key
    
    # Azure Key Vault specific
    azureKeyVault:
      vaultUrl: https://my-vault.vault.azure.net
      keyName: my-key
      keyVersion: ""  # Optional, uses latest if empty
    
    # YubiKey PIV specific (for bare metal)
    yubikey:
      slot: 9a  # PIV slot
      publicKeyFingerprint: SHA256:xxxxx
    
    # TPM 2.0 specific (for bare metal)
    tpm:
      pcrSelection:
        hash: sha256
        pcrs: [0, 1, 2, 3, 7]
    
    # The encrypted blob (base64-encoded)
    ciphertext: <base64-encoded-encrypted-age-private-key>
  
  # Identity attestation requirements
  attestation:
    # For cloud providers: OIDC-based identity
    oidc:
      issuer: https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716
      audience: sts.amazonaws.com
      subject: system:serviceaccount:genesis-system:genesis-operator
    
    # For AWS IRSA
    awsIrsa:
      roleArn: arn:aws:iam::123456789012:role/genesis-operator-role
    
    # For GCP Workload Identity
    gcpWorkloadIdentity:
      serviceAccount: genesis-operator@my-project.iam.gserviceaccount.com
  
  # Output configuration
  output:
    # Where to create the decryption secret
    secretName: sops-age
    secretNamespace: flux-system
    secretKey: age.agekey
    
    # Optional: also create in additional namespaces
    additionalNamespaces: []

status:
  conditions:
    - type: Ready
      status: "True"
      lastTransitionTime: "2024-01-15T10:00:00Z"
      reason: DecryptionKeyProvisioned
      message: "Age decryption key successfully provisioned to flux-system/sops-age"
  
  # Last successful attestation
  lastAttestation:
    time: "2024-01-15T10:00:00Z"
    provider: aws-kms
    identity: arn:aws:sts::123456789012:assumed-role/genesis-operator-role/...
  
  # Key metadata (no sensitive data)
  keyMetadata:
    publicKey: age1xxxxxxxxx...
    createdAt: "2024-01-01T00:00:00Z"
    algorithm: X25519
```

#### GenesisRotationPolicy (Future)

```yaml
apiVersion: genesis.io/v1alpha1
kind: GenesisRotationPolicy
metadata:
  name: database-credentials
  namespace: genesis-system
spec:
  # Source secret to rotate
  source:
    kind: Secret
    name: postgres-credentials
    namespace: app
  
  # Rotation schedule
  schedule:
    interval: 720h  # 30 days
    
  # Rotation strategy
  strategy:
    type: BlueGreen  # Create new before revoking old
    overlapPeriod: 24h
    
  # Notification on rotation
  notify:
    - type: Event
    - type: Slack
      channel: "#platform-alerts"
      webhookSecretRef:
        name: slack-webhook
        key: url
```

## CLI Specification

### Commands

```bash
# Initialize a new genesis configuration
genesis init \
  --provider aws-kms \
  --key-arn arn:aws:kms:us-west-2:123456789012:key/... \
  --output ./clusters/production/genesis/

# Verify a genesis configuration can be decrypted (requires identity)
genesis verify ./clusters/production/genesis/genesis-bootstrap.yaml

# Rotate the master key (re-encrypt with new envelope)
genesis rotate \
  --config ./clusters/production/genesis/genesis-bootstrap.yaml \
  --new-key-arn arn:aws:kms:us-west-2:123456789012:key/new-key

# Generate a new SOPS-encrypted secret
genesis seal \
  --config ./clusters/production/genesis/ \
  --input secret.yaml \
  --output secret.enc.yaml

# Decrypt a SOPS-encrypted secret (for debugging, requires identity)
genesis unseal \
  --config ./clusters/production/genesis/ \
  --input secret.enc.yaml

# Show status of genesis in a cluster
genesis status --context my-cluster
```

### Flags

```
Global Flags:
  --config string       Path to genesis configuration directory
  --verbose            Enable verbose output
  --json               Output in JSON format

Init Flags:
  --provider string    KMS provider (aws-kms, gcp-kms, azure-keyvault, yubikey, tpm)
  --key-arn string     AWS KMS key ARN
  --key-name string    GCP KMS key name
  --vault-url string   Azure Key Vault URL
  --slot string        YubiKey PIV slot (default: 9a)
  --pcrs string        TPM PCR selection (comma-separated)
  --output string      Output directory for genesis files
```

## Security Model

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Compromised git repository | Secrets encrypted with age; age key encrypted with KMS |
| Compromised cluster etcd | Age key only in memory during reconciliation; optional memory-only mode |
| Stolen cloud credentials | KMS permissions scoped to specific key; requires both key access AND identity attestation |
| Malicious operator deployment | ServiceAccount must match expected OIDC subject claim |
| Key exfiltration from operator | Key never written to disk; cleared from memory after secret creation |

### Trust Boundaries

1. **KMS Provider**: We trust the cloud KMS to protect the envelope key
2. **Identity Provider**: We trust OIDC/IRSA/Workload Identity attestation
3. **Kubernetes RBAC**: We trust cluster RBAC to protect the decryption secret
4. **Git Repository**: We trust git access controls for the encrypted configuration

### Key Material Handling

1. Master age private key is **never** stored in plaintext outside of:
   - Operator memory during decryption (cleared immediately after)
   - Kubernetes Secret in the target namespace
2. The envelope (KMS-encrypted blob) can be safely stored in git
3. SOPS-encrypted secrets use the age public key (safe to distribute)

## Implementation Plan

### Phase 1: Core CLI (v0.1.0)

- [ ] `genesis init` with AWS KMS provider
- [ ] `genesis verify` for testing decryption
- [ ] `genesis seal` / `genesis unseal` for SOPS operations
- [ ] Comprehensive unit tests for crypto operations
- [ ] Integration tests with LocalStack for KMS

### Phase 2: Kubernetes Operator (v0.2.0)

- [ ] GenesisBootstrap CRD and controller
- [ ] AWS IRSA identity provider
- [ ] Flux integration (Kustomization decryption secret)
- [ ] Helm chart for deployment
- [ ] E2E tests with kind + LocalStack

### Phase 3: Multi-Provider Support (v0.3.0)

- [ ] GCP KMS + Workload Identity
- [ ] Azure Key Vault + AAD Pod Identity
- [ ] YubiKey PIV for bare metal
- [ ] TPM 2.0 attestation

### Phase 4: Advanced Features (v0.4.0)

- [ ] GenesisRotationPolicy CRD
- [ ] GitHub Actions OIDC integration
- [ ] Multi-cluster federation
- [ ] Audit logging

## Testing Strategy

### Unit Tests

- All crypto operations (age encrypt/decrypt, KMS envelope)
- Configuration parsing and validation
- Error handling and edge cases

### Integration Tests

- AWS KMS operations via LocalStack
- Kubernetes API interactions via envtest
- SOPS file operations

### E2E Tests

- Full bootstrap flow with kind cluster
- Flux integration and secret decryption
- Multi-cluster scenarios

## Dependencies

### Go Libraries

```go
require (
    filippo.io/age v1.2.0                           // Age encryption
    github.com/aws/aws-sdk-go-v2 v1.30.0            // AWS SDK
    github.com/getsops/sops/v3 v3.9.0               // SOPS integration
    k8s.io/api v0.31.0                              // Kubernetes API
    k8s.io/apimachinery v0.31.0                     // Kubernetes types
    k8s.io/client-go v0.31.0                        // Kubernetes client
    sigs.k8s.io/controller-runtime v0.19.0          // Operator framework
)
```

### External Dependencies

- Kubernetes 1.28+
- Flux v2.3.0+
- AWS KMS / GCP KMS / Azure Key Vault (cloud providers)
- age-plugin-yubikey (for YubiKey support)

## References

- [age encryption format](https://github.com/FiloSottile/age)
- [SOPS](https://github.com/getsops/sops)
- [Flux SOPS integration](https://fluxcd.io/flux/guides/mozilla-sops/)
- [AWS KMS Envelope Encryption](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping)
- [Kubernetes Workload Identity](https://kubernetes.io/docs/concepts/security/service-accounts/)
- [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime)
