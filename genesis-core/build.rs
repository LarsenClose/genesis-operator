fn main() {
    // cbindgen header generation is done via the cbindgen CLI tool,
    // not in build.rs, to avoid build-time dependency on cbindgen.
    // Run: cbindgen --config cbindgen.toml --output genesis_core.h
    //
    // This build.rs exists for future use (e.g., linking flags).
}
