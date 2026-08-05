//! Integration tests that read JSON fixtures produced by the foundry harness
//! `test/petal/PetalE2E.t.sol` against the REAL 0xBOW contracts. The fixture
//! path is `/tmp/opencode/goal-pp-e2e/fixtures/` by convention; these tests
//! are skipped (not failed) if the fixtures are absent so `cargo test` still
//! passes on a machine that hasn't run the forge harness.
//!
//! To regenerate the fixtures (from inside the `0xbow-io/privacy-pools-core`
//! checkout):
//!   forge test --mp test/petal/PetalE2E.t.sol -vv

use alloy_primitives::{Address, U256};
use privacy_pools_route::commitment::{commitment_hash, precommitment_hash};
use privacy_pools_route::deposit::parse_deposited_in;

const FIXTURE_DIR: &str = "/tmp/opencode/goal-pp-e2e/fixtures";

fn fixtures_present() -> bool {
    std::path::Path::new(&format!("{FIXTURE_DIR}/deposited-1.json")).exists()
}

fn read_json(name: &str) -> serde_json::Value {
    let text = std::fs::read_to_string(format!("{FIXTURE_DIR}/{name}"))
        .unwrap_or_else(|e| panic!("read {name}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn u256_of(v: &serde_json::Value) -> U256 {
    // forge serializes large uints as decimal strings and small uints as JSON
    // numbers — accept both.
    if let Some(s) = v.as_str() {
        return U256::from_str_radix(s, 10).unwrap();
    }
    if let Some(i) = v.as_u64() {
        return U256::from(i);
    }
    panic!("u256_of: unexpected value type {v:?}");
}

fn addr_of(v: &serde_json::Value) -> Address {
    v.as_str().unwrap().parse().unwrap()
}

/// Build a receipt JSON in the shape the parser expects, from the flat fields
/// the foundry fixture writes (`address`, `topic0`, `topic1_depositor`, `data`).
fn single_log_receipt(log: &serde_json::Value) -> String {
    let receipt_log = serde_json::json!({
        "address": log["address"],
        "topics": [log["topic0"], log["topic1_depositor"]],
        "data": log["data"],
    });
    serde_json::json!({ "logs": [receipt_log] }).to_string()
}

/// Phase-2 round-trip: the real emitted `Deposited` logs from the canonical
/// 0xBOW contracts must parse with the petal's fixed layout, and the parsed
/// commitment must equal the petal's own `commitment_hash(value, label, pre)`
/// (cross-checking the parser, the hash3 port, and the ABI against on-chain
/// `PoseidonT4`). The emitted value must equal `msg.value − vetting fee`.
#[test]
fn real_deposits_parse_and_match_commitment_math() {
    if !fixtures_present() {
        eprintln!("skipping: fixtures absent (run the PetalE2E forge test first)");
        return;
    }
    let addrs = read_json("addresses.json");
    let pool = addr_of(&addrs["pool"]);
    let notes = read_json("notes.json");
    let amt = u256_of(&notes["amount_wei"]);
    let vetting_bps = u256_of(&addrs["vetting_fee_bps"]);
    let after_fee = amt - (amt * vetting_bps) / U256::from(10_000u64);

    for n in 1..=3u32 {
        let fix = read_json(&format!("deposited-{n}.json"));
        let receipt = single_log_receipt(&fix);
        let parsed = parse_deposited_in(&receipt, &[pool])
            .unwrap_or_else(|| panic!("deposit {n}: parser returned None for a real log"));

        // c9 integrity against the real on-chain PoseidonT4.
        let recomputed = commitment_hash(parsed.value, parsed.label, parsed.precommitment);
        assert_eq!(
            recomputed, parsed.commitment,
            "deposit {n}: commitment != poseidon([value,label,precommitment])"
        );

        // Fee math: emitted _value == msg.value - vetting fee.
        assert_eq!(
            parsed.value, after_fee,
            "deposit {n}: emitted value != amount-after-fee"
        );

        // The parsed precommitment must equal poseidon2([nullifier, secret])
        // from the stored note.
        let pre_key = format!("{}_precommitment", n - 1);
        let note_pre = u256_of(&notes[pre_key]);
        assert_eq!(
            parsed.precommitment, note_pre,
            "deposit {n}: precommitment diverges from note"
        );
        // And it must match recomputing from the note's nullifier/secret.
        let nullifier = u256_of(&notes[format!("{}_nullifier", n - 1)]);
        let secret = u256_of(&notes[format!("{}_secret", n - 1)]);
        assert_eq!(
            precommitment_hash(nullifier, secret),
            parsed.precommitment,
            "deposit {n}: precommitment != poseidon2([nullifier,secret])"
        );
    }
}

/// p4 (tamper): mutating one byte of the commitment in the real receipt's
/// `data` makes the integrity check fail (`commitment_hash` no longer matches).
#[test]
fn real_receipt_tampered_commitment_is_rejected() {
    if !fixtures_present() {
        eprintln!("skipping: fixtures absent");
        return;
    }
    let addrs = read_json("addresses.json");
    let pool = addr_of(&addrs["pool"]);
    let fix = read_json("deposited-1.json");
    let receipt = single_log_receipt(&fix);
    let parsed = parse_deposited_in(&receipt, &[pool]).unwrap();
    let recomputed = commitment_hash(parsed.value, parsed.label, parsed.precommitment);
    assert_eq!(recomputed, parsed.commitment, "baseline must be valid");

    // Flip one byte in the commitment word (first 32 bytes of data).
    let mut data_bytes: Vec<u8> =
        hex::decode(fix["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    data_bytes[0] ^= 0x01; // flip the low bit of the first byte
    let data_hex = hex::encode(&data_bytes);
    let mut tampered = fix.clone();
    tampered["data"] = serde_json::Value::String(format!("0x{data_hex}"));
    let tampered_receipt = single_log_receipt(&tampered);
    let tparsed = parse_deposited_in(&tampered_receipt, &[pool]).unwrap();
    let trecomputed = commitment_hash(tparsed.value, tparsed.label, tparsed.precommitment);
    assert_ne!(
        trecomputed, tparsed.commitment,
        "tampered commitment must NOT equal recomputed hash"
    );
}
