/// Genesis<Active> should not expose key_material.
/// The `key_material` field only exists on GenesisBootstrapping
/// and is private. Genesis<Active> has no such field at all.

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
    let active = bootstrapping.inject_secret(&injector, "s", "ns", "k").unwrap();

    // ERROR: no field `key_material` on type `Genesis<Active>`
    let _km = &active.key_material;
}
