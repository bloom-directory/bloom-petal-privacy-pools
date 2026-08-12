//! Compatibility entry point for the removed diagnostic prover.
//!
//! The previous example accepted secret-bearing JSON and invoked unpinned
//! `snarkjs` paths. Use the supported companion instead.

fn main() {
    eprintln!(
        "Use tools/privacy-pools/cli.mjs prepare; see WITHDRAWAL.md for the secure workflow."
    );
    std::process::exit(2);
}
