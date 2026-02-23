/// Genesis<Initialized> should not have an `inject_secret()` method.
/// Only GenesisBootstrapping provides inject_secret.

use genesis_core::audit::NullAuditSink;
use genesis_core::kms::NullKmsProvider;
use genesis_core::state::{Genesis, GenesisConfig};

fn main() {
    let config = GenesisConfig {
        provider_type: "null-dev".to_string(),
        provider_config: serde_json::json!({}),
        public_key: None,
        envelope_ciphertext: None,
    };
    let g = Genesis::new(config, Box::new(NullAuditSink));
    let kms = NullKmsProvider;
    let (initialized, _artifacts) = g.init(&kms).unwrap();

    // ERROR: Genesis<Initialized> has no method named `inject_secret`
    let _ = initialized.inject_secret(&genesis_core::k8s::MockSecretInjector::new(), "s", "ns", "k");
}
