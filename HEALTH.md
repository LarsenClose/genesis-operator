# Genesis Operator Health Assessment

Phase transition: Phases 1-8 complete. Full rotation API surface wired end-to-end.

## What's Working Well

- **Security invariant enforced end-to-end**: BridgeBootstrapInjector is the default path. Key material never enters Go memory in production. check-key-material scan enforces this across internal/bridge/, internal/controller/, cmd/.
- **Complete rotation API surface**: begin_rotation, complete_rotation, and abort_rotation all exposed through the full stack (Rust -> FFI -> Go bridge). BridgeRotationExecutor wired into all 3 strategies (BlueGreen, Rolling, Immediate).
- **Comprehensive test coverage**: 202 Rust tests, 17 Go packages, CI with full quality gates (fmt, clippy, tests, security, coverage, helm lint, docker, trivy).
- **Rust state machine**: Compile-time enforced typestate transitions. Rotation states (Active -> Rotating -> Active) with FFI bindings for the complete lifecycle.
- **SecretMetadata traceability**: bootstrap-name and bootstrap-namespace labels on managed secrets link back to originating GenesisBootstrap CR.
- **CLI output contract**: Regression tests validate exact output filenames, YAML structure, and permissions.
- **Helm chart**: Production-ready with security context, IRSA support, metrics/health probes.
- **CI/CD**: All gates enforced, Dependabot + auto-merge configured, golangci-lint v2 built from source (Go 1.26.1 compat).

## What's Not Working

- **Identity filename mismatch**: genesis writes genesis-identity.key, launch expects age-identity.txt. Blocks full secrets pipeline. Requires cross-project coordination to resolve.
- **No multi-cloud KMS integration tests**: Requires real provider credentials (AWS KMS, GCP KMS, Azure Key Vault). Currently mocked.
- **No E2E tests against live cluster**: Kind-based tests for full bootstrap and rotation lifecycle not yet implemented.
- **LegacyBootstrapInjector exists for test compatibility only**: Controller tests use Go KMS decrypt path because the bridge creates secrets via ureq HTTP (incompatible with controller-runtime fake client). Not a security issue (production uses bridge) but adds code surface and complexity.

## What Would Improve Things

1. **Fix identity filename mismatch** (highest priority, cross-project): Align genesis output filename with launch expectations to unblock the full secrets pipeline.
2. **Scheduled rotation automation**: Rotation verification, rollback on failure, automated health checks post-rotation.
3. **Multi-cloud KMS integration testing**: Real provider credential testing in CI (gated/scheduled).
4. **Helm chart integration with deploy repo**: End-to-end deployment workflow validation.
5. **Prometheus metrics for rotation events**: Rotation duration, success/failure counts, secret age. Observable operations.

## Current Metrics

| Metric | Value |
|--------|-------|
| Rust tests | 202 |
| Go test packages | 17 |
| CI status | Green (9efa1bc) |
| Latest release | v0.5.0 (2026-03-06) |
| Open issues | 1 (filename mismatch - to be created) |
| CRDs | GenesisBootstrap, GenesisRotationPolicy |
| Helm chart | charts/genesis-operator/ |
| Security gates | cargo-audit, govulncheck, gosec, trivy, check-key-material |
