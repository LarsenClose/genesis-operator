//! Kubeconfig parsing and authentication helpers.
//!
//! Provides utilities for extracting cluster credentials from a kubeconfig
//! file, primarily for out-of-cluster operation during local development
//! and CI.

/// Parse a kubeconfig file and return the API server URL, bearer token,
/// and optional CA certificate bundle for the current context.
///
/// This is a simplified line-based parser that handles the most common
/// kubeconfig format (flat structure with `server:`, `token:`, and
/// `certificate-authority:` fields).  It does **not** resolve context
/// indirection -- it simply finds the first occurrence of each field.
///
/// # Errors
///
/// Returns `GenesisError::K8sAuthFailed` if the file cannot be read or
/// does not contain a `server:` field.
pub fn from_kubeconfig(
    path: &str,
) -> Result<(String, String, Option<Vec<u8>>), crate::GenesisError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        crate::GenesisError::K8sAuthFailed(format!("failed to read kubeconfig: {e}"))
    })?;

    // Extract server URL (look for "server:" line)
    let server = content
        .lines()
        .find(|l| l.trim().starts_with("server:"))
        .and_then(|l| l.trim().strip_prefix("server:"))
        .map(|s| s.trim().trim_matches('"').to_string())
        .ok_or_else(|| {
            crate::GenesisError::K8sAuthFailed("no server found in kubeconfig".into())
        })?;

    // Extract token if present (look for "token:" line)
    let token = content
        .lines()
        .find(|l| l.trim().starts_with("token:"))
        .and_then(|l| l.trim().strip_prefix("token:"))
        .map(|s| s.trim().trim_matches('"').to_string())
        .unwrap_or_default();

    // CA cert -- try to read from certificate-authority field
    let ca_cert = content
        .lines()
        .find(|l| l.trim().starts_with("certificate-authority:"))
        .and_then(|l| l.trim().strip_prefix("certificate-authority:"))
        .map(|s| s.trim().trim_matches('"').to_string())
        .and_then(|p| std::fs::read(p).ok());

    Ok((server, token, ca_cert))
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_kubeconfig() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kc_path = dir.path().join("kubeconfig");
        std::fs::write(
            &kc_path,
            r#"apiVersion: v1
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: dev
contexts:
- context:
    cluster: dev
    user: admin
  name: dev
current-context: dev
users:
- name: admin
  user:
    token: my-bearer-token
"#,
        )
        .expect("write kubeconfig");

        let (server, token, ca) =
            from_kubeconfig(kc_path.to_str().unwrap()).expect("parse should succeed");
        assert_eq!(server, "https://127.0.0.1:6443");
        assert_eq!(token, "my-bearer-token");
        assert!(ca.is_none());
    }

    #[test]
    fn parse_kubeconfig_missing_server() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kc_path = dir.path().join("kubeconfig");
        std::fs::write(&kc_path, "apiVersion: v1\nkind: Config\n").expect("write");

        let err = from_kubeconfig(kc_path.to_str().unwrap());
        assert!(err.is_err());
    }

    #[test]
    fn parse_kubeconfig_no_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kc_path = dir.path().join("kubeconfig");
        std::fs::write(
            &kc_path,
            "apiVersion: v1\nclusters:\n- cluster:\n    server: https://localhost:6443\n",
        )
        .expect("write");

        let (server, token, _) =
            from_kubeconfig(kc_path.to_str().unwrap()).expect("parse should succeed");
        assert_eq!(server, "https://localhost:6443");
        assert!(token.is_empty());
    }

    #[test]
    fn parse_kubeconfig_nonexistent_file() {
        let err = from_kubeconfig("/nonexistent/path/kubeconfig");
        assert!(err.is_err());
    }

    #[test]
    fn parse_kubeconfig_with_ca_cert() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca_path = dir.path().join("ca.crt");
        std::fs::write(&ca_path, b"FAKE-CA-CERT-DATA").expect("write ca");

        let kc_path = dir.path().join("kubeconfig");
        std::fs::write(
            &kc_path,
            format!(
                "apiVersion: v1\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443\n    certificate-authority: {}\nusers:\n- name: admin\n  user:\n    token: tok123\n",
                ca_path.display()
            ),
        )
        .expect("write kubeconfig");

        let (server, token, ca) =
            from_kubeconfig(kc_path.to_str().unwrap()).expect("parse should succeed");
        assert_eq!(server, "https://10.0.0.1:6443");
        assert_eq!(token, "tok123");
        assert_eq!(ca.as_deref(), Some(b"FAKE-CA-CERT-DATA".as_slice()));
    }
}
