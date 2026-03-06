# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-03-06

### Added
- **Security invariant restoration** (Phase 4): `BootstrapInjector` strategy pattern — production path (`BridgeBootstrapInjector`) keeps all key material in Rust memory; legacy path (`LegacyBootstrapInjector`) retained for test compatibility and `AdditionalNamespaces` support
- **KMS config JSON bridge** (Phase 3): Go credential resolution feeds Rust KMS providers via `BuildKmsConfigJSON()`, enabling cloud-native auth (IRSA, Workload Identity, Instance Principal) to flow through the FFI boundary
- **UreqSecretInjector enrichment** (Phase 2): Labels, annotations, TLS CA verification, and FFI metadata propagation for Rust-side K8s secret injection
- **Dependabot auto-merge workflow**: Dependency update PRs auto-merge when all CI gates pass

### Fixed
- Mock-dependent CLI tests guarded behind `genesis_mock` build tag (no longer fail in release builds)
- Rust build target with `--features mock` for Go bridge test compatibility
- Raw JSON manifest digest extraction in release workflow

### Security
- Controller no longer holds plaintext key material in Go memory (restored invariant: all cryptographic operations execute in Rust)

## [0.4.0] - 2026-03-01

### Added
- **Post-quantum cryptography**: ML-DSA-87 / ML-KEM-1024 key generation and envelope operations in genesis-core
- **Local provider**: Standalone mode for development and testing without cloud KMS
- **PQ crypto Go integration**: Bridge and CLI wiring for post-quantum operations
- Comprehensive test coverage for PQ crypto Go integration

### Changed
- Native arm64 runners + cache mounts for Docker builds

### Security
- Production hardening of genesis-core (input validation, error handling, memory safety audit)

### Fixed
- SOPS_AGE_KEY_FILE path `nosec` annotation (G703)
- Release workflow test failures and arm64 push permissions
- OCI labels on Dockerfile for GHCR auto-linking
- PAT authentication for GHCR push in release workflow

## [0.3.0] - 2026-02-22

### Added
- **Rust Cryptographic Core (`genesis-core`)**: All key material operations now execute in a Rust
  static library linked into Go via CGO, eliminating private key exposure in the Go memory space
  - Age X25519 keypair generation (Rust-native)
  - Envelope seal/unseal via Rust-side age encryption
  - C FFI bridge with cbindgen-generated headers
  - Go bridge layer (`internal/bridge/`) provides safe Go-callable interface
- **OCI Vault Provider**: Full envelope encryption/decryption support for Oracle Cloud Infrastructure Vault
  - Uses OCI KMS crypto endpoints for encrypt/decrypt operations
  - Supports Instance Principal authentication for OKE workloads
  - Compatible with OCI Vault free tier (20 HSM key versions, unlimited software keys)
- Improved mock provider error handling (no more panics)
- Configurable operator logging mode (production vs development)
- Enhanced KMS registry documentation

### Breaking Changes
- Build now requires CGO (`CGO_ENABLED=1`) due to Rust static library linkage
- `go install` no longer works without pre-built Rust artifacts; use `make build-cli` or Docker
- Standalone binary releases are linux/amd64 only; arm64 is available via Docker image (multi-arch)

### Changed
- Release pipeline produces Docker images (multi-arch linux/amd64 + linux/arm64) as the primary
  distribution; standalone binary is linux/amd64 only (cross-platform binaries deferred to a
  future release with cargo-zigbuild)
- 3-stage Dockerfile: Rust build, Go build (with CGO), distroless runtime
- CI pipeline restructured: Rust job builds static library and uploads as artifact;
  Go test/lint/build/security jobs consume the artifact
- Updated Dockerfile to use Go 1.24

### Security
- Private key material never enters Go heap -- all cryptographic operations execute in Rust
- `make check-key-material` gate verifies no unexpected key references leak into Go layer

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

[Unreleased]: https://github.com/larsenclose/genesis-operator/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/larsenclose/genesis-operator/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/larsenclose/genesis-operator/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/larsenclose/genesis-operator/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/larsenclose/genesis-operator/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/larsenclose/genesis-operator/releases/tag/v0.1.0
