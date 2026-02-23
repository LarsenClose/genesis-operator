/// There is no direct Initialized -> Active transition.
/// The only path is Initialized -> Bootstrapping -> Active
/// (via begin_bootstrap + inject_secret).
/// Attempting to call begin_rotation() on Genesis<Initialized>
/// should fail because that method only exists on Genesis<Active>.

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
    let (initialized, _) = g.init(&kms).unwrap();

    // ERROR: no method named `begin_rotation` found for struct `Genesis<Initialized>`
    let _rotating = initialized.begin_rotation();
}
