# Genesis

[![CI](https://github.com/LarsenClose/genesis-operator/actions/workflows/ci.yml/badge.svg)](https://github.com/LarsenClose/genesis-operator/actions/workflows/ci.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/LarsenClose/genesis-operator)](https://goreportcard.com/report/github.com/LarsenClose/genesis-operator) [![codecov](https://codecov.io/gh/LarsenClose/genesis-operator/branch/main/graph/badge.svg)](https://codecov.io/gh/LarsenClose/genesis-operator) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**Universal GitOps Secrets Bootstrap**

Genesis solves the "chicken-and-egg" problem in GitOps secrets management: you need secrets to deploy secrets managers, but your secrets manager is supposed to manage your secrets.

Genesis provides a single, identity-based bootstrap mechanism that works across cloud providers (AWS, GCP, Azure, OCI) and bare-metal environments (YubiKey, TPM 2.0), requiring only one manual step (key generation) and then enabling fully automated, declarative secrets lifecycle management.

## Key Features

- **Envelope Encryption**: KMS encrypts age key, age encrypts secrets - avoids KMS API limits and enables offline secret management
- **Identity-Based Access**: Clusters prove identity cryptographically via OIDC/IRSA/Workload Identity/Instance Principal, not pre-shared secrets
- **GitOps Native**: All configuration lives in git, operator is fully declarative
- **Multi-Cloud Support**: AWS KMS, GCP Cloud KMS, Azure Key Vault, OCI Vault
- **Bare-Metal Support**: YubiKey PIV and TPM 2.0 interfaces (requires external provider libraries)
- **SOPS Integration**: Works seamlessly with existing SOPS workflows and Flux

## Installation

### CLI

> **Note:** Building from source requires the Rust toolchain (see `rust-toolchain.toml`) and CGO.
> `go install` does not work without pre-built Rust artifacts. Use `make build-cli` for the recommended build path.

```bash
git clone https://github.com/larsenclose/genesis
cd genesis
make build-cli
```

### Operator

```bash
# Using Helm
helm upgrade --install genesis-operator charts/genesis-operator \
  --namespace genesis-system --create-namespace

# Or with kubectl
kubectl apply -f config/crd/bases/
kubectl apply -f charts/genesis-operator/templates/
```

## Quick Start

### 1. Initialize Bootstrap Configuration

```bash
# AWS KMS
genesis init \
  --provider aws-kms \
  --key-arn arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012 \
  --output ./clusters/production/genesis/

# GCP KMS
genesis init \
  --provider gcp-kms \
  --key-name projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key \
  --output ./clusters/production/genesis/

# Azure Key Vault
genesis init \
  --provider azure-keyvault \
  --vault-url https://my-vault.vault.azure.net \
  --az-key-name my-key \
  --output ./clusters/production/genesis/

# OCI Vault
genesis init \
  --provider oci-vault \
  --key-ocid ocid1.key.oc1.us-phoenix-1.abc123... \
  --crypto-endpoint https://abc123-crypto.kms.us-phoenix-1.oraclecloud.com \
  --output ./clusters/production/genesis/
```

This generates:
- `genesis-bootstrap.yaml` - Envelope-encrypted master key (safe for git)
- `.sops.yaml` - SOPS configuration pointing to your age public key

### 2. Encrypt Your Secrets with SOPS

```bash
genesis seal --config ./genesis-bootstrap.yaml --input secret.yaml --output secret.enc.yaml

# Or use SOPS directly
sops --encrypt --config .sops.yaml secret.yaml > secret.enc.yaml
```

### 3. Deploy the Operator

The operator watches for `GenesisBootstrap` resources and:
1. Proves cluster identity via cloud provider (IRSA, Workload Identity, etc.)
2. Decrypts the envelope to obtain the age private key
3. Creates a Kubernetes Secret for SOPS/Flux decryption

```yaml
apiVersion: genesis.io/v1alpha1
kind: GenesisBootstrap
metadata:
  name: cluster-secrets
  namespace: genesis-system
spec:
  envelope:
    provider: aws-kms
    awsKms:
      keyArn: arn:aws:kms:us-west-2:123456789012:key/...
      region: us-west-2
    ciphertext: <base64-encoded-encrypted-age-key>
  output:
    secretName: sops-age
    secretNamespace: flux-system
    secretKey: age.agekey
```

### 4. Configure Flux for Decryption

```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: my-app
  namespace: flux-system
spec:
  decryption:
    provider: sops
    secretRef:
      name: sops-age
  # ... rest of kustomization
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `genesis init` | Initialize a new genesis configuration |
| `genesis seal` | Encrypt a secret file using SOPS |
| `genesis unseal` | Decrypt a SOPS-encrypted secret file |
| `genesis verify` | Verify a genesis configuration can be decrypted |
| `genesis rotate` | Rotate the master key by re-encrypting with a new envelope |
| `genesis version` | Print version information |

Use `genesis <command> --help` for detailed usage.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    INITIALIZATION (One-time)                     │
│  $ genesis init --provider aws-kms --key-arn ...                │
│                                                                  │
│  1. Generate age X25519 keypair (master key)                    │
│  2. Encrypt private key with KMS (envelope encryption)          │
│  3. Output genesis-bootstrap.yaml + .sops.yaml                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    GIT REPOSITORY                                │
│  clusters/production/                                            │
│    ├── genesis/genesis-bootstrap.yaml  # Encrypted master key   │
│    └── secrets/*.enc.yaml              # SOPS-encrypted secrets │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    KUBERNETES CLUSTER                            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ genesis-operator                                            │ │
│  │   1. Watch GenesisBootstrap CRD                            │ │
│  │   2. Prove identity (IRSA/Workload Identity/OIDC)          │ │
│  │   3. Decrypt envelope → obtain age private key             │ │
│  │   4. Create Secret: flux-system/sops-age                   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Flux Kustomization                                          │ │
│  │   - References decryption secret                           │ │
│  │   - Decrypts SOPS secrets during reconciliation            │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Security Architecture

Genesis Operator enforces a strict security boundary: **all key material operations execute in a Rust static library** (`genesis-core`) linked into the Go binary via CGO.

```
genesis CLI / K8s Controller (Go)
        |
        v
   CGO Bridge (internal/bridge/)
        |
        v
   genesis-core (Rust static library)
   ├── Typestate machine (6 states, compile-time enforced)
   ├── KeyMaterial (Zeroizing + mlock, no Clone/Debug/Serialize)
   ├── KMS providers (AWS, GCP, Azure, OCI Vault)
   └── age X25519 envelope crypto
```

**Build prerequisites:** Rust toolchain (see `rust-toolchain.toml`), `cbindgen`, and `CGO_ENABLED=1`.

## Security Model

### Envelope Encryption

Genesis uses envelope encryption to protect the master key:
1. An age X25519 keypair is generated locally
2. The private key is encrypted by your KMS provider
3. The encrypted blob (envelope) is stored in git
4. Only entities with KMS decrypt permissions AND matching identity can recover the key

### Identity Attestation

Clusters prove their identity cryptographically:
- **AWS**: IRSA (IAM Roles for Service Accounts)
- **GCP**: Workload Identity
- **Azure**: AAD Pod Identity
- **GitHub Actions**: OIDC tokens with repository/workflow claims

### Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Compromised git repository | Secrets encrypted with age; age key encrypted with KMS |
| Compromised cluster etcd | Age key only in memory; optional memory-only mode |
| Stolen cloud credentials | KMS permissions scoped; requires identity attestation |
| Key exfiltration | Key never written to disk; cleared from memory after use |

## CRDs

### GenesisBootstrap

Manages the bootstrap lifecycle for a cluster.

```yaml
apiVersion: genesis.io/v1alpha1
kind: GenesisBootstrap
spec:
  envelope:
    provider: aws-kms | gcp-kms | azure-keyvault | oci-vault | yubikey | tpm
    # Provider-specific configuration
    ciphertext: <base64-encoded-encrypted-age-key>
  attestation:  # Optional identity requirements
    oidc:
      issuer: https://...
      subject: system:serviceaccount:...
  output:
    secretName: sops-age
    secretNamespace: flux-system
```

### GenesisRotationPolicy

Declares rotation schedules for secrets (coming soon).

```yaml
apiVersion: genesis.io/v1alpha1
kind: GenesisRotationPolicy
spec:
  source:
    kind: Secret
    name: my-secret
  schedule:
    interval: 720h  # 30 days
  strategy:
    type: BlueGreen
    overlapPeriod: 24h
```

## Development

```bash
# Run tests
make test

# Run tests with filtered coverage (excludes auto-generated code)
make test-filtered

# Generate coverage report
./scripts/coverage-report.sh --html

# Run linters
make lint

# Build binaries
make build

# Build Docker image
make docker-build

# Run E2E tests (requires kind)
make e2e
```

See [docs/COVERAGE.md](docs/COVERAGE.md) for details on test coverage configuration and metrics.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Security

For security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Acknowledgments

Genesis builds on excellent open source projects:
- [age](https://github.com/FiloSottile/age) - Modern encryption tool
- [SOPS](https://github.com/getsops/sops) - Secrets OPerationS
- [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime) - Kubernetes operator framework
- [Flux](https://fluxcd.io/) - GitOps toolkit
