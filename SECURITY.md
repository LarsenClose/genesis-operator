# Security Policy

## Supported Versions

We release security patches for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please send an email to LarsenClose@pm.me with:

1. A description of the vulnerability
2. Steps to reproduce the issue
3. Potential impact assessment
4. Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Assessment**: We will assess the vulnerability and determine its severity
- **Timeline**: We aim to provide a fix within 90 days, depending on complexity
- **Disclosure**: We will coordinate disclosure timing with you

### Severity Levels

We use the following severity classifications:

| Severity | Description | Response Time |
|----------|-------------|---------------|
| Critical | Remote code execution, key exfiltration | 24-48 hours |
| High | Authentication bypass, privilege escalation | 1 week |
| Medium | Information disclosure, denial of service | 2 weeks |
| Low | Minor issues with limited impact | 30 days |

## Security Model

Genesis is designed with security as a primary concern. Key security features:

### Envelope Encryption

- Master age keypair is never stored in plaintext
- Private key is encrypted by cloud KMS (AWS, GCP, Azure) or hardware (YubiKey, TPM)
- Decryption requires both KMS access AND identity attestation

### Identity Attestation

- Clusters prove identity cryptographically via OIDC
- Supports AWS IRSA, GCP Workload Identity, GitHub Actions OIDC
- No pre-shared secrets required

### Key Material Handling

- Age private key only exists in memory during decryption
- Key is cleared from memory immediately after use
- Kubernetes Secrets use standard Kubernetes RBAC protection

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Compromised git repo | Secrets encrypted with age; age key encrypted with KMS |
| Compromised etcd | Age key only in memory; optional memory-only mode |
| Stolen cloud credentials | KMS permissions scoped; requires identity attestation |
| Key exfiltration | Key never written to disk; cleared after use |

## Security Best Practices

When using Genesis:

1. **Limit KMS permissions**: Only grant decrypt permissions to the genesis-operator ServiceAccount
2. **Use identity attestation**: Always configure OIDC/IRSA/Workload Identity constraints
3. **Rotate regularly**: Use GenesisRotationPolicy to automate envelope rotation
4. **Audit logs**: Enable and monitor genesis audit logging
5. **RBAC**: Restrict access to GenesisBootstrap resources and output Secrets

## Dependencies

We regularly update dependencies to include security patches. Check our `go.mod` for current versions.

To scan for known vulnerabilities:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

## Acknowledgments

We appreciate security researchers who responsibly disclose vulnerabilities. Contributors will be acknowledged (with permission) in release notes.
