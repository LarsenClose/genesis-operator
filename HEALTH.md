# Genesis Operator Health Assessment

Phase transition: Phases 1-5 complete, shifting to medium-term goals.

## What's Working Well

- **Security invariant enforced in production**: BridgeBootstrapInjector is the default path. Key material never enters Go memory in production.
- **Comprehensive test infrastructure**: 193 Rust tests, 17 Go packages, CI with 9-job pipeline (fmt, clippy, tests, security, coverage, helm lint, docker, trivy, e2e).
- **Rust state machine**: Compile-time enforced typestate transitions. Rotation states (Active -> Rotating -> Active) already implemented with FFI bindings.
- **Bridge FFI**: Complete coverage of state machine operations including BeginRotation/CompleteRotation/AbortRotation.
- **Rotation scaffold**: CRD types, controller (730 lines), 3 strategies, notification system (Slack, Webhook, PagerDuty, K8s Events), tests (1376 lines).
- **Helm chart**: Production-ready with security context, IRSA support, metrics/health probes.
- **CI/CD**: All gates enforced, Dependabot configured, auto-merge on green CI.

## What's Not Working

- **Rotation controller is a scaffold**: All three strategies (BlueGreen, Rolling, Immediate) only update annotations. No actual key regeneration, no bridge integration, no envelope re-encryption. The Rust bridge rotation FFI exists but is not called.
- **LegacyBootstrapInjector exists for test compatibility only**: Controller tests use Go KMS decrypt path because the bridge creates secrets via ureq HTTP (incompatible with controller-runtime fake client). Not a security issue (production uses bridge) but adds code surface and complexity.
- **check-key-material scan is narrow**: Only covers `internal/bridge/` and `cmd/`. Should include `internal/controller/` per TODO in Makefile.

## What Would Improve Things

1. **Wire rotation controller to bridge**: Connect performRotation strategies to bridge.BeginRotation/CompleteRotation FFI. This is the highest-leverage medium-term work.
2. **Design RotationPolicy -> GenesisBootstrap linkage**: Rotation needs to find the GenesisBootstrap CR that created the target secret to access KMS config for cryptographic rotation.
3. **Add Prometheus metrics**: Rotation events, bootstrap duration, secret age. Observable operations.
4. **E2E rotation tests**: Kind-based tests for the full rotation lifecycle.

## Current Metrics

| Metric | Value |
|--------|-------|
| Rust tests | 193 |
| Go test packages | 17 |
| CI status | Green (138c18f) |
| Latest release | v0.5.0 (2026-03-06) |
| Open issues | 0 |
| CRDs | GenesisBootstrap, GenesisRotationPolicy |
| Helm chart | charts/genesis-operator/ |
| Security gates | cargo-audit, govulncheck, gosec, trivy, check-key-material |
