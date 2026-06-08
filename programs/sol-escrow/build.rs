// The Solana `entrypoint!` macro expands to code gated on cfgs that aren't part of
// our crate — `target_os = "solana"` and the `custom-heap` / `custom-panic` features.
// Declaring them here keeps the `unexpected_cfgs` lint quiet when the crate is checked
// on the host (rust-analyzer, `cargo check`) or built for BPF, without a `[lints]`
// table in Cargo.toml.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(target_os, values(\"solana\"))");
    println!("cargo::rustc-check-cfg=cfg(feature, values(\"custom-heap\", \"custom-panic\"))");
}
