/// Genesis<Uninitialized> should not have an `unseal()` method.
/// Only Genesis<Initialized> provides unseal.

use genesis_core::audit::NullAuditSink;
use genesis_core::state::{Genesis, GenesisConfig, Uninitialized};

fn main() {
    let config = GenesisConfig {
        provider_type: "null-dev".to_string(),
        provider_config: serde_json::json!({}),
        public_key: None,
        envelope_ciphertext: None,
    };
    let g: Genesis<Uninitialized> = Genesis::new(config, Box::new(NullAuditSink));

    // ERROR: Genesis<Uninitialized> has no method named `unseal`
    let _ = g.unseal(&genesis_core::kms::NullKmsProvider, b"ciphertext");
}
