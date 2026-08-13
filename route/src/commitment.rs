//! Privacy Pools commitment math, ported from `packages/sdk/src/crypto.ts`.
//!
//! Commitment scheme (0xBOW):
//!   * `precommitmentHash = poseidon([nullifier, secret])`
//!   * `commitmentHash    = poseidon([value, label, precommitmentHash])`
//!   * `label             = keccak256(abi.encode(scope, nonce))`
//!
//! The on-chain pool computes `label` from its own `SCOPE` and an incremental
//! `nonce`, then inserts `commitmentHash` into its LeanIMT. The depositor reads
//! the emitted `label`/`commitment` back from the `Deposited` event, so this
//! module only needs to *reproduce* those values (e.g. to verify a stored note
//! against an on-chain leaf) and to derive the precommitment that goes into the
//! deposit transaction.

use alloy_primitives::U256;
use sha3::{Digest, Keccak256};

use crate::field::FIELD_P;
use crate::poseidon::{hash1, hash2, hash3};

/// `keccak256` of the big-endian 32-byte words, reduced into the BN254 scalar
/// field. Matches `snarkHash()` / Solidity `keccak256(...) % p` usage.
#[must_use]
pub fn keccak_words(words: &[U256]) -> U256 {
    let mut hasher = Keccak256::new();
    for word in words {
        hasher.update(word.to_be_bytes::<32>());
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    U256::from_be_bytes(bytes) % FIELD_P
}

/// `label = keccak256(abi.encode(scope, nonce)) % p`.
#[must_use]
pub fn label(scope: U256, nonce: U256) -> U256 {
    keccak_words(&[scope, nonce])
}

/// `precommitmentHash = poseidon([nullifier, secret])`. This is the value passed
/// to `Entrypoint.deposit(precommitment)`. It is distinct from the spent
/// nullifier hash, which is `poseidon([nullifier])`.
#[must_use]
pub fn precommitment_hash(nullifier: U256, secret: U256) -> U256 {
    hash2(nullifier, secret)
}

/// `commitmentHash = poseidon([value, label, precommitment])`. This is the leaf
/// inserted into the pool's state LeanIMT and emitted as `_commitment`.
#[must_use]
pub fn commitment_hash(value: U256, label: U256, precommitment: U256) -> U256 {
    hash3(value, label, precommitment)
}

/// A fully-resolved deposit note. `nullifier`/`secret` MUST stay private; only
/// the derived fields are safe to expose publicly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub value: U256,
    pub label: U256,
    pub nullifier: U256,
    pub secret: U256,
}

impl Note {
    pub fn new(value: U256, label: U256, nullifier: U256, secret: U256) -> Self {
        Self {
            value,
            label,
            nullifier,
            secret,
        }
    }

    pub fn precommitment(&self) -> U256 {
        precommitment_hash(self.nullifier, self.secret)
    }

    pub fn commitment(&self) -> U256 {
        commitment_hash(self.value, self.label, self.precommitment())
    }

    /// The nullifier hash marked spent on-chain is `poseidon([nullifier])`.
    pub fn nullifier_hash(&self) -> U256 {
        hash1(self.nullifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_deterministic_and_matches_scheme() {
        let n = Note::new(
            U256::from(1_000_000_000_000_000_000u128),
            label(U256::from(42), U256::from(7)),
            U256::from(0xaaaa),
            U256::from(0xbbbb),
        );
        assert_eq!(
            n.commitment(),
            commitment_hash(n.value, n.label, n.precommitment())
        );
        assert_eq!(n.nullifier_hash(), hash1(n.nullifier));
        assert_ne!(n.nullifier_hash(), n.precommitment());
    }

    #[test]
    fn label_matches_keccak_of_packed_words() {
        // Independent recomputation via a fresh hasher.
        let scope = U256::from(0x1234);
        let nonce = U256::from(0x5678);
        let mut h = Keccak256::new();
        h.update(scope.to_be_bytes::<32>());
        h.update(nonce.to_be_bytes::<32>());
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&h.finalize());
        let want = U256::from_be_bytes(buf) % FIELD_P;
        assert_eq!(label(scope, nonce), want);
    }
}
