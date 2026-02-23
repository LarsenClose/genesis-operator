/// KeyMaterial intentionally does not implement Clone.
/// Any attempt to clone it should be a compile error.

use genesis_core::KeyMaterial;

fn main() {
    let km = KeyMaterial::new(vec![1, 2, 3, 4]);

    // ERROR: the method `clone` exists but `KeyMaterial` doesn't implement `Clone`
    let _km2 = km.clone();
}
