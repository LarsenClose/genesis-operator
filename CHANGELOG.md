# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **OCI Vault Provider**: Full envelope encryption/decryption support for Oracle Cloud Infrastructure Vault
  - Uses OCI KMS crypto endpoints for encrypt/decrypt operations
  - Supports Instance Principal authentication for OKE workloads
  - Compatible with OCI Vault free tier (20 HSM key versions, unlimited software keys)
- Improved mock provider error handling (no more panics)
- Configurable operator logging mode (production vs development)
- Enhanced KMS registry documentation

### Changed
- Updated Dockerfile to use Go 1.24

## [0.2.0] - 2026-01-27

### Added
- **Core Cryptography**: age X25519 keypair generation with envelope encryption pattern
- **AWS KMS Provider**: Full envelope encryption/decryption with IRSA identity attestation
- **GCP KMS Provider**: Full envelope encryption/decryption with integrity verification and Workload Identity
- **Azure Key Vault Provider**: Full envelope encryption/decryption with AAD Pod Identity
- **YubiKey PIV Provider**: Interface complete for hardware security module support (requires piv-go CGO library)
- **TPM 2.0 Provider**: Interface complete for Trusted Platform Module support (requires go-tpm CGO library)
- **CLI Tool**: Complete command set
  - `genesis init` - Generate age keypair and encrypt with KMS
  - `genesis seal` - Encrypt files with SOPS using age public key
  - `genesis unseal` - Decrypt SOPS files using KMS-decrypted age private key
  - `genesis verify` - Verify bootstrap configuration can be decrypted
  - `genesis rotate` - Re-encrypt envelope with new KMS key
  - `genesis version` - Display version information
- **GenesisBootstrap Controller**: Kubernetes operator for automated secret provisioning
  - Secret creation in target namespace
  - Multi-namespace secret distribution
  - Finalizer-based cleanup
  - Status conditions and attestation tracking
- **GenesisRotationPolicy Controller**: Automated secret rotation with zero-downtime
  - Scheduled rotation with cron expressions
  - Blue-green rotation strategy with overlap periods
  - Webhook, Slack, and PagerDuty notification support
- **GitHub OIDC Verification**: JWT validation with JWKS caching
  - Policy-based authorization (repository, workflow, environment, actor)
- **AWS IRSA Attestation**: Identity verification for EKS workloads
- **GCP Workload Identity Attestation**: Identity verification for GKE workloads
- **Audit Logging**: Structured JSON audit events
  - Event types: bootstrap, decrypt, rotation, attestation, auth failures
  - Resource and actor tracking
  - Multi-logger support (file-based and no-op)
- **Configuration Management**: YAML-based bootstrap configuration
  - SOPS configuration generation
  - Validation and schema enforcement
- **Helm Chart**: Complete deployment package
  - CRDs included
  - IRSA annotation support
  - Pod security contexts configured

### Security
- Age private key never stored unencrypted
- Identity-based KMS access (no static credentials)
- Audit log for all secret operations
- OIDC token verification with JWKS validation

## [0.1.0] - 2026-01-01

### Added
- Initial project structure
- Basic age encryption support
- AWS KMS integration prototype
- CLI scaffolding with Cobra

[Unreleased]: https://github.com/larsenclose/genesis/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/larsenclose/genesis/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/larsenclose/genesis/releases/tag/v0.1.0
