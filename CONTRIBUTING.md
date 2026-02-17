# Contributing to Genesis

Thank you for your interest in contributing to Genesis. This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this standard. Please report unacceptable behavior to the maintainers.

## Getting Started

### Prerequisites

- Go 1.24 or later
- Docker (for building container images)
- Helm 3.x (for Kubernetes deployment)
- kubectl (for testing with Kubernetes)
- kind (for local E2E testing)

### Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/larsenclose/genesis.git
   cd genesis
   ```

2. Install dependencies:
   ```bash
   go mod download
   ```

3. Run tests:
   ```bash
   make test
   ```

4. Build binaries:
   ```bash
   make build
   ```

## Development Workflow

### Making Changes

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the coding standards below

3. Run the full verification suite:
   ```bash
   make verify
   ```

4. Commit your changes with a descriptive message

5. Push your branch and create a pull request

### Pull Request Process

1. Ensure all CI checks pass
2. Update documentation if needed
3. Add tests for new functionality
4. Request review from maintainers
5. Address review feedback
6. Squash commits if requested

## Coding Standards

### Go Code

- Follow the [Effective Go](https://golang.org/doc/effective_go.html) guidelines
- Use `gofmt` for formatting (run `make fmt`)
- Pass `golangci-lint` (run `make lint`)
- Write tests for new functionality
- Keep functions focused and small
- Use meaningful variable and function names
- Add comments for exported functions and types

### Commit Messages

- Use the imperative mood ("Add feature" not "Added feature")
- Keep the first line under 72 characters
- Reference issues when relevant (e.g., "Fixes #123")
- Separate subject from body with a blank line

Example:
```
Add AWS KMS provider support

Implement envelope encryption using AWS KMS for the genesis init command.
This enables users to bootstrap secrets management using their existing
AWS KMS infrastructure.

Fixes #42
```

### Testing

- Write unit tests for new functions
- Use table-driven tests where appropriate
- Mock external dependencies
- Aim for >80% code coverage on new code
- Run the full test suite before submitting:
  ```bash
  make test
  ```

### Documentation

- Update README.md for user-facing changes
- Add inline comments for complex logic
- Update SPEC.md for architectural changes
- Include examples in documentation

## Project Structure

```
genesis/
├── cmd/
│   ├── genesis/     # CLI application
│   └── operator/    # Kubernetes operator
├── internal/
│   ├── audit/       # Audit logging
│   ├── config/      # Configuration management
│   ├── controller/  # Kubernetes controllers
│   ├── crypto/      # Age encryption
│   ├── envelope/    # Envelope encryption
│   ├── identity/    # Identity providers (AWS, GCP, GitHub)
│   └── kms/         # KMS providers (AWS, GCP, Azure, YubiKey, TPM)
├── pkg/
│   └── api/         # CRD type definitions
├── charts/          # Helm chart
├── config/          # Kubernetes manifests
└── test/            # E2E tests
```

## Running E2E Tests

E2E tests require a kind cluster:

```bash
# Create cluster and run tests
make e2e

# Or run steps individually
make kind-create
make docker-build
make kind-load
make install-crds
make e2e-test
make kind-delete
```

## Generating Code

After modifying CRD types in `pkg/api/v1alpha1/types.go`:

```bash
make generate
```

This updates:
- DeepCopy methods
- CRD YAML manifests
- Helm chart CRDs

## Security

If you discover a security vulnerability, please follow the process in [SECURITY.md](SECURITY.md). Do not open a public issue for security vulnerabilities.

## Questions

If you have questions about contributing:

1. Check existing issues and discussions
2. Open a new issue with your question
3. Join our community channels (if available)

## License

By contributing to Genesis, you agree that your contributions will be licensed under the Apache License 2.0.
