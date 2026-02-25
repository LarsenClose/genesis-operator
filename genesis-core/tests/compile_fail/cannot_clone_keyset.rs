/// GenesisKeySet intentionally does not implement Clone.
/// Private keys must not be duplicated.

fn main() {
    let keyset = genesis_core::GenesisKeySet::generate().unwrap();

    // ERROR: the method `clone` exists but `GenesisKeySet` doesn't implement `Clone`
    let _copy = keyset.clone();
}
