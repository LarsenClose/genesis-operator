/// GenesisBootstrapping::inject_secret() consumes self.
/// A second call on the same binding must fail with "use of moved value".

use genesis_core::audit::NullAuditSink;
use genesis_core::k8s::MockSecretInjector;
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
    let (initialized, _) = g.init(&kms).unwrap();
    let bootstrapping = initialized.begin_bootstrap(&kms).unwrap();

    let injector = MockSecretInjector::new();

    // First call consumes `bootstrapping`.
    let _active = bootstrapping.inject_secret(&injector, "s", "ns", "k").unwrap();

    // ERROR: use of moved value: `bootstrapping`
    let _active2 = bootstrapping.inject_secret(&injector, "s2", "ns", "k");
}
