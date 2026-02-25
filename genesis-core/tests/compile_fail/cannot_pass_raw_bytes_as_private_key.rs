/// Private key parameters require &KeyMaterial, not &[u8].
/// Passing raw bytes must be a compile error.

fn main() {
    let raw_bytes: &[u8] = &[1, 2, 3, 4];

    // ERROR: expected `&KeyMaterial`, found `&[u8]`
    let _ = genesis_core::crypto::pq::mlkem_decapsulate(raw_bytes, &[]);
}
