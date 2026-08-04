//! BN254 scalar-field arithmetic used by Privacy Pools commitments.
//!
//! All on-chain commitments, nullifiers, and LeanIMT node hashes are computed
//! in the scalar field of the BN254 pairing curve (the "SNARK scalar field").
//! This module exposes the modulus and the modular helpers the Poseidon and
//! LeanIMT code need. It deliberately uses `alloy_primitives::U256` so no extra
//! big-integer dependency is required inside the WASM component.

use alloy_primitives::U256;

/// BN254 scalar field modulus `p`, also known as the SNARK scalar field:
/// `21888242871839275222246405745257275088548364400416034343698204186575808495617`.
pub const FIELD_P: U256 = U256::from_limbs([
    0x43e1_f593_f000_0001,
    0x2833_e848_79b9_7091,
    0xb850_45b6_8181_585d,
    0x3064_4e72_e131_a029,
]);

/// Reduce a `U256` into the BN254 scalar field. `U256` values are already in
/// `[0, 2^256)`, so a single modular reduction is sufficient.
#[inline]
pub fn reduce(a: U256) -> U256 {
    a % FIELD_P
}

/// Parse a hex field element (with or without `0x`) and reduce it.
pub fn from_hex(s: &str) -> Option<U256> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() || s.bytes().any(|b| !b.is_ascii_hexdigit()) {
        return None;
    }
    U256::from_str_radix(s, 16).ok().map(reduce)
}

/// Field addition.
#[inline]
pub fn add(a: U256, b: U256) -> U256 {
    a.add_mod(b, FIELD_P)
}

/// Field multiplication.
#[inline]
pub fn mul(a: U256, b: U256) -> U256 {
    a.mul_mod(b, FIELD_P)
}

/// `x^5 mod p`, the Poseidon S-box.
#[inline]
pub fn pow5(x: U256) -> U256 {
    let x2 = mul(x, x);
    let x4 = mul(x2, x2);
    mul(x4, x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modulus_matches_snark_scalar_field() {
        let expected =
            "21888242871839275222246405745257275088548364400416034343698204186575808495617";
        assert_eq!(FIELD_P.to_string(), expected);
    }

    #[test]
    fn reduction_is_idempotent_below_modulus() {
        let a = from_hex("0x123456789abcdef").unwrap();
        assert_eq!(reduce(a), a);
    }
}
