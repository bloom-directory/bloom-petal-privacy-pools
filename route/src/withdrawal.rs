//! Withdrawal proof-input preparation.
//!
//! Withdrawing from a Privacy Pool requires a Groth16 proof
//! (`snarkjs.groth16.fullProve`) over the withdrawal circuit. Generating that
//! proof needs the circuit wasm + a trusted-setup zkey and runs for seconds,
//! so it stays **out of the petal** (it is also privacy-critical that proving
//! happens locally). This module prepares everything that *is* the petal's job:
//! the note's public commitment/nullifier, the withdrawal context hash, the
//! current roots, and the exact witness field schema the circuit consumes.
//!
//! The state/ASP Merkle proofs require syncing the deposit tree from
//! `Deposited` events and the ASP set; a route handler is the wrong place to do
//! that bulk sync, so those two fields are returned as `null` with instructions.

use alloy_primitives::{Address, U256};
use petal::DispatchResponse;

use crate::field::FIELD_P;
use crate::notes;
use crate::protocol::{CHAIN, POOL_ETH};

fn err(code: i32, msg: impl Into<String>) -> DispatchResponse {
    petal::error(code, msg)
}

/// `abi.encode((address processooor, bytes data), uint256 scope)` for the
/// direct-withdrawal context (empty `data`).
pub fn encode_context(processooor: Address, data: &[u8], scope: U256) -> Vec<u8> {
    let mut out = Vec::new();
    // head[0] = offset to the (processooor,data) tuple tail = 64
    out.extend_from_slice(&U256::from(64u64).to_be_bytes::<32>());
    // head[1] = scope
    out.extend_from_slice(&scope.to_be_bytes::<32>());
    // tuple tail:
    let mut addr = [0u8; 32];
    addr[12..].copy_from_slice(processooor.as_ref());
    out.extend_from_slice(&addr); // tuple head[0] = processooor
    // tuple head[1] = offset to bytes within tuple = 64
    out.extend_from_slice(&U256::from(64u64).to_be_bytes::<32>());
    // bytes tail:
    out.extend_from_slice(&U256::from(data.len() as u64).to_be_bytes::<32>());
    out.extend_from_slice(data);
    while out.len() % 32 != 0 {
        out.push(0);
    }
    out
}

/// `context = uint256(keccak256(abi.encode((processooor, data), scope))) % p`.
pub fn context_hash(processooor: Address, data: &[u8], scope: U256) -> U256 {
    let enc = encode_context(processooor, data, scope);
    let mut hasher = sha3::Keccak256::new();
    use sha3::Digest;
    hasher.update(&enc);
    let digest = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&digest);
    U256::from_be_bytes(buf) % FIELD_P
}

/// Read-only withdrawal-input preview for a note.
pub fn prepare(wallet: &str, id: &str) -> DispatchResponse {
    if let Err(e) = notes::validate_idents(wallet, id) {
        return err(-3, e);
    }
    let note = match notes::load_note(wallet, id) {
        Ok(Some(n)) => n,
        Ok(None) => return err(-1, "no such deposit"),
        Err(e) => return err(-4, e),
    };

    let commitment = match &note.commitment {
        Some(c) => c.clone(),
        None => return err(-3, "deposit is not confirmed yet; reconcile it first"),
    };
    let label = note.label.clone().unwrap_or_default();
    let value = note.value.clone().unwrap_or_default();
    let nullifier_hash = note.precommitment.clone();

    // Best-effort live roots (not required to prepare, but useful).
    let (asp_root, tree_size, scope) =
        match crate::chain::asset_config(crate::protocol::NATIVE_ASSET) {
            Ok((pool, _min, _vet, _max)) => {
                let asp = crate::chain::latest_asp_root().ok();
                let size = crate::chain::current_tree_size(pool).ok();
                let scope = crate::chain::pool_scope(pool).ok();
                (asp, size, scope)
            }
            Err(_) => (None, None, None),
        };

    // A worked example context for a direct (self-recipient) withdrawal. The
    // real recipient is chosen at proving time. We only emit it when the live
    // scope is known — falling back to a garbage scope would produce a context
    // that no on-chain withdrawal could ever match (c4).
    let example_context = scope.map(|s| {
        format!(
            "0x{:x}",
            context_hash(
                // placeholder recipient zero-address; caller recomputes with the real one
                Address::ZERO,
                &[],
                s,
            )
        )
    });

    let body = serde_json::json!({
        "petal": "privacy-pools",
        "chain": CHAIN,
        "pool": format!("{POOL_ETH:?}"),
        "asset": note.asset,
        "note": {
            "commitment": commitment,
            "label": label,
            "value": value,
            "nullifier_hash": nullifier_hash,
        },
        "roots": {
            "asp_root": asp_root.map(|r| format!("0x{:x}", r)),
            "state_tree_size": tree_size.map(|s| s.to_string()),
            "scope": scope.map(|s| format!("0x{:x}", s)),
        },
        "withdrawal_proof_input": {
            "public_signals": {
                "withdrawnValue": value,
                "stateRoot": null,            // fill from synced state tree root
                "stateTreeDepth": null,
                "ASPRoot": asp_root.map(|r| format!("0x{:x}", r)),
                "ASPTreeDepth": null,
                "context": example_context,
            },
            "private_signals": {
                "label": label,
                "existingValue": value,
                "existingNullifier": note.nullifier,
                "existingSecret": note.secret,
                "newNullifier": null,         // fresh random field element
                "newSecret": null,            // fresh random field element
            },
            "merkle_proofs": {
                "stateSiblings": null,        // LeanIMT proof of the note commitment
                "stateIndex": null,
                "ASPSiblings": null,          // LeanIMT proof of the note label in the ASP set
                "ASPIndex": null,
            }
        },
        "proof_generation": "out-of-petal: snarkjs.groth16.fullProve(input, withdraw.wasm, withdraw.zkey)",
        "instructions": "Fill the null fields by syncing the pool's Deposited events into a LeanIMT (state tree) and fetching the ASP set, then prove and submit via the official SDK or relayer."
    });
    petal::read_json_value(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_is_field_reduced_and_deterministic() {
        let scope = U256::from(0x42);
        let c1 = context_hash(Address::ZERO, &[], scope);
        let c2 = context_hash(Address::ZERO, &[], scope);
        assert_eq!(c1, c2);
        assert!(c1 < FIELD_P);
    }

    #[test]
    fn encode_context_has_expected_length_for_empty_data() {
        // head(64) + tuple(addr 32 + offset 32) + bytes(len 32) = 160 bytes.
        let enc = encode_context(Address::ZERO, &[], U256::from(7));
        assert_eq!(enc.len(), 160);
    }

    #[test]
    fn context_changes_with_processooor() {
        let scope = U256::from(1);
        let a = context_hash(Address::ZERO, &[], scope);
        let other = Address::from_slice(&[1u8; 20]);
        let b = context_hash(other, &[], scope);
        assert_ne!(a, b);
    }
}
