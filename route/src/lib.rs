//! Privacy Pools (0xBOW) protocol domain code shared by this Petal's route
//! components: BN254 field arithmetic, Poseidon hashing, commitment math,
//! LeanIMT, deposit workflow, on-chain reads, and withdrawal proof-input
//! preparation.

pub mod chain;
pub mod commitment;
pub mod deposit;
pub mod field;
pub mod lean_imt;
pub mod notes;
pub mod poseidon;
mod poseidon_constants;
pub mod protocol;
pub mod types;
pub mod withdrawal;

pub use serde_json;
