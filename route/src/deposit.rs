//! ETH deposit workflow: generate a note, derive the precommitment, stage the
//! `Entrypoint.deposit(precommitment)` transaction through Bloom's tx outbox,
//! persist the private note + public status, and reconcile the `Deposited` log
//! from the receipt once mined.

use alloy_primitives::U256;
use petal::{DispatchResponse, EvmTransaction, HostStatus, OutboxInspection, sdk};

use crate::commitment::{commitment_hash, precommitment_hash};
use crate::field::reduce;
use crate::notes;
use crate::protocol::{
    CHAIN, ENTRYPOINT, NATIVE_ASSET, POOL_ETH, deposit_eth_selector, deposited_topic0,
};
use crate::types::{DepositRequest, DepositStatus, StoredNote, TxRef};

/// Build `deposit(uint256 precommitment)` calldata (4 + 32 bytes).
#[must_use]
pub fn build_eth_deposit_calldata(precommitment: U256) -> Vec<u8> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&deposit_eth_selector());
    data.extend_from_slice(&precommitment.to_be_bytes::<32>());
    data
}

/// Parse a decimal-wei amount string and validate it is non-zero.
pub fn validate_amount(amount_wei: &str) -> Result<U256, String> {
    let value = U256::from_str_radix(amount_wei.trim(), 10)
        .map_err(|_| "amount_wei is not a decimal integer")?;
    if value == U256::ZERO {
        return Err("amount_wei must be greater than zero".into());
    }
    Ok(value)
}

/// A cryptographically random BN254 field element, drawn from the host RNG.
pub fn random_field() -> Result<U256, String> {
    for _ in 0..3 {
        let bytes = sdk::random_bytes(32).map_err(|e| e.message())?;
        let mut buf = [0u8; 32];
        if bytes.len() == 32 {
            buf.copy_from_slice(&bytes);
            let x = reduce(U256::from_be_bytes(buf));
            if x != U256::ZERO {
                return Ok(x);
            }
        }
    }
    Err("host RNG did not yield a non-zero field element".into())
}

fn err(code: i32, msg: impl Into<String>) -> DispatchResponse {
    petal::error(code, msg)
}

/// Result of inspecting a possibly-existing note for the same `<id>`.
///
/// This is the policy core of `create`'s idempotency: it decides whether a
/// retry should re-stage, return the existing deposit, or refuse. Keeping it
/// pure makes the partial-failure behaviour unit-testable without a host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateAttempt {
    /// No prior note (or a definitively-failed one): proceed to stage.
    NewDeposit,
    /// A prior note exists with a different amount — refuse to clobber it.
    Conflict,
    /// A prior staging attempt left the note mid-flight (placeholder written,
    /// stage outcome uncertain). Refuse to re-stage to avoid a double-spend.
    Incomplete,
    /// A prior note exists for the same amount and reached a terminal-enough
    /// state; return it via the read path instead of re-staging.
    Retry,
}

/// Classify an existing note against the requested amount. `existing` is the
/// previously-stored note for this `<id>`, if any.
#[must_use]
pub fn classify_existing(existing: Option<&StoredNote>, requested_amount: U256) -> CreateAttempt {
    let Some(note) = existing else {
        return CreateAttempt::NewDeposit;
    };
    // Compare numeric amounts, not the string forms (the stored string is the
    // canonical decimal form, so a string compare would also work, but this is
    // robust to a caller that supplied e.g. a leading zero).
    let stored = U256::from_str_radix(note.amount_wei.trim(), 10).unwrap_or(U256::ZERO);
    if stored != requested_amount {
        return CreateAttempt::Conflict;
    }
    match note.status.as_str() {
        // Placeholder written before staging whose stage call did not return
        // (process died) or whose post-stage persist did not complete.
        "staging" => CreateAttempt::Incomplete,
        // Stage was attempted and definitively failed; same id may retry.
        "stage-failed" => CreateAttempt::NewDeposit,
        // Reached the outbox (or beyond): idempotent re-read.
        "staged" | "confirmed" | "failed" | "reverted" => CreateAttempt::Retry,
        // Unknown status from a future version — treat conservatively as a
        // retry so we never re-stage.
        _ => CreateAttempt::Retry,
    }
}

/// Stage a deposit. `wallet` is a Bloom wallet alias; `id` is a caller-chosen
/// durable idempotency key.
///
/// Idempotency / partial-failure contract (c2): a `"staging"` placeholder is
/// persisted (claiming the id) BEFORE the host `tx_stage` call. If staging
/// fails the placeholder is marked `"stage-failed"` (retryable with the same
/// id). If staging succeeds the placeholder is advanced to `"staged"`. As a
/// result `tx_stage` is invoked **at most once per `<id>`**; the only
/// irreducible window is the host stage call itself returning without us
/// observing the result, which surfaces as `"staging"` (Incomplete).
pub fn create(wallet: &str, id: &str, body: &[u8]) -> DispatchResponse {
    if let Err(e) = notes::validate_idents(wallet, id) {
        return err(-3, e);
    }
    if body.len() > 8 * 1024 {
        return err(-3, "request body is too large");
    }
    let request: DepositRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return err(-3, format!("invalid request JSON: {e}")),
    };
    if !matches!(request.asset.as_deref(), None | Some("eth")) {
        return err(-3, "only asset \"eth\" is supported");
    }
    let amount = match validate_amount(&request.amount_wei) {
        Ok(v) => v,
        Err(e) => return err(-3, e),
    };

    // Idempotency / partial-failure recovery.
    let prior = match notes::load_note(wallet, id) {
        Ok(n) => n,
        Err(e) => return err(-4, e),
    };
    match classify_existing(prior.as_ref(), amount) {
        CreateAttempt::Retry => return crate::deposit::read(wallet, id),
        CreateAttempt::Conflict => {
            return err(
                -3,
                "a deposit already exists for this id with a different amount; use a new id",
            );
        }
        CreateAttempt::Incomplete => {
            return err(
                -3,
                "a previous staging attempt for this id did not complete cleanly; \
                 use a new id or ask the operator to inspect the outbox",
            );
        }
        CreateAttempt::NewDeposit => {}
    }
    let prior_was_failed = prior
        .as_ref()
        .map(|n| n.status == "stage-failed")
        .unwrap_or(false);

    // Best-effort minimum-deposit check against on-chain asset config.
    match crate::chain::asset_config(NATIVE_ASSET) {
        Ok((_pool, min, _vet, _max)) if amount < min => {
            return err(
                -3,
                format!("amount is below the pool minimum deposit ({min})"),
            );
        }
        Ok(_) => {}
        Err(e) => return err(-4, format!("could not read pool config: {e}")),
    }

    let nullifier = match random_field() {
        Ok(v) => v,
        Err(e) => return err(-4, e),
    };
    let secret = match random_field() {
        Ok(v) => v,
        Err(e) => return err(-4, e),
    };
    let precommitment = precommitment_hash(nullifier, secret);

    // Build the placeholder note and atomically claim the id BEFORE staging.
    // The empty `outbox_id` + `status = "staging"` records that a stage attempt
    // is in flight; a retry that observes this state refuses to re-stage.
    let placeholder = StoredNote {
        wallet: wallet.to_string(),
        asset: "eth".to_string(),
        amount_wei: amount.to_string(),
        nullifier: format!("0x{nullifier:x}"),
        secret: format!("0x{secret:x}"),
        precommitment: format!("0x{precommitment:x}"),
        status: "staging".to_string(),
        tx: TxRef {
            chain: CHAIN.to_string(),
            outbox_id: String::new(),
            tx_hash: None,
        },
        value: None,
        label: None,
        commitment: None,
        spent: false,
        approval_action_id: None,
        approval_ceremony_url: None,
        approval_expires_ms: None,
    };
    let claim = if prior_was_failed {
        notes::upsert_note_by_id(&placeholder, wallet, id)
    } else {
        notes::store_note_by_id(&placeholder, wallet, id)
    };
    if let Err(e) = claim {
        return err(
            -3,
            format!("could not claim deposit id (race or retry): {e}"),
        );
    }

    let calldata = build_eth_deposit_calldata(precommitment);
    let staged = match sdk::tx_stage(&EvmTransaction {
        wallet: wallet.to_string(),
        chain: CHAIN.to_string(),
        to: format!("{ENTRYPOINT:?}"),
        value_wei: amount.to_string(),
        data_hex: format!("0x{}", hex::encode(&calldata)),
        nonce: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    }) {
        Ok(s) => s,
        Err(petal::SdkError::Host(HostStatus::Denied)) => {
            mark_stage_failed(wallet, id, &placeholder, "denied by the host");
            return err(-2, "deposit staging was denied by the host");
        }
        Err(e) => {
            mark_stage_failed(wallet, id, &placeholder, &e.message());
            return err(-4, format!("failed to stage deposit: {}", e.message()));
        }
    };

    let mut note = placeholder;
    note.status = "staged".to_string();
    note.tx.outbox_id = staged.outbox_id.clone();
    note.approval_action_id = staged.approval.as_ref().map(|a| a.action_id.clone());
    note.approval_ceremony_url = staged.approval.as_ref().map(|a| a.ceremony_url.clone());
    note.approval_expires_ms = staged.approval.as_ref().map(|a| a.expires_ms);

    if let Err(e) = notes::persist_update(&note, wallet, id) {
        // The tx IS staged; the note is still in the `"staging"` placeholder
        // state, so a retry will classify as Incomplete rather than re-staging.
        // Surface the outbox_id so the operator can reconcile by hand.
        return err(
            -4,
            format!(
                "deposit staged (outbox_id={}) but persist failed; retry or inspect the outbox. cause: {e}",
                staged.outbox_id
            ),
        );
    }
    DispatchResponse::Write
}

/// Record that a staging attempt definitively failed, so the same `<id>` can be
/// retried cleanly. Overwrites the placeholder in place (the SDK has no
/// secret-namespace delete, so we tombstone instead).
fn mark_stage_failed(wallet: &str, id: &str, placeholder: &StoredNote, reason: &str) {
    let mut failed = placeholder.clone();
    failed.status = "stage-failed".to_string();
    // Reuse the unused `label` field as a free-form diagnostic for the operator.
    // It is never set for a successful deposit, so this is unambiguous.
    failed.label = Some(format!("stage-failed: {reason}"));
    let _ = notes::upsert_note_by_id(&failed, wallet, id);
}

/// Read and reconcile a deposit's status. Re-inspects the outbox and, on
/// confirmation, parses the `Deposited` log to fill `label`/`value`/`commitment`.
pub fn read(wallet: &str, id: &str) -> DispatchResponse {
    if let Err(e) = notes::validate_idents(wallet, id) {
        return err(-3, e);
    }
    let mut note = match notes::load_note(wallet, id) {
        Ok(Some(n)) => n,
        Ok(None) => return err(-1, "no such deposit"),
        Err(e) => return err(-4, e),
    };
    if let Err(e) = reconcile(&mut note, wallet, id) {
        return err(-4, e);
    }
    petal::read_json_value(&DepositStatus::from(&note))
}

/// Reconcile a note against its staged transaction by inspecting the outbox.
/// Mutates `note` and, on a transition, re-persists both the private note and
/// the public status.
pub fn reconcile(note: &mut StoredNote, wallet: &str, id: &str) -> Result<(), String> {
    let inspection = sdk::tx_inspect(wallet, CHAIN, &note.tx.outbox_id).map_err(|e| e.message())?;
    reconcile_with(note, wallet, id, &inspection)
}

/// Outcome of [`apply_reconciliation`]: whether the note changed and therefore
/// needs to be re-persisted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reconciliation {
    Unchanged,
    Updated,
}

/// Pure-logic core of [`reconcile`], parameterised by the outbox inspection.
/// Extracted so the reconciliation policy is unit-testable without a host
/// (c6 self-heal, c9 commitment integrity).
///
/// Re-parse policy (c6): on every `confirmed` read we re-attempt to parse the
/// `Deposited` log from the receipt (the previous `commitment.is_none()` gate
/// meant a transiently-malformed receipt could permanently corrupt the note).
pub fn apply_reconciliation(
    note: &mut StoredNote,
    inspection: &OutboxInspection,
) -> Result<Reconciliation, String> {
    let mut changed = false;

    if note.tx.tx_hash != inspection.tx_hash {
        note.tx.tx_hash = inspection.tx_hash.clone();
        changed = true;
    }

    let new_status = match inspection.state.as_str() {
        "confirmed" | "mined" | "success" => "confirmed",
        "failed" | "reverted" => "failed",
        other => other,
    };
    if note.status != new_status {
        note.status = new_status.to_string();
        changed = true;
    }

    if new_status == "confirmed"
        && let Some(receipt) = inspection.receipt_json.as_deref()
        && let Some(parsed) = parse_deposited(receipt)
    {
        // Tamper / integrity guard (c9): the emitted commitment must equal
        // poseidon([value, label, precommitment]). A mismatch means either the
        // receipt was tampered with or our hash diverged from the on-chain
        // circuit — either way, refuse to record it.
        let recomputed = commitment_hash(parsed.value, parsed.label, parsed.precommitment);
        if recomputed != parsed.commitment {
            return Err(
                "receipt commitment does not match poseidon([value,label,precommitment])".into(),
            );
        }
        // Ownership: the spent nullifier hash must be this note's precommitment.
        if format!("0x{:x}", parsed.precommitment) != note.precommitment {
            return Err("receipt precommitment does not match this note".into());
        }
        let new_commitment = Some(format!("0x{:x}", parsed.commitment));
        let new_label = Some(format!("0x{:x}", parsed.label));
        let new_value = Some(parsed.value.to_string());
        if note.commitment != new_commitment {
            note.commitment = new_commitment;
            changed = true;
        }
        if note.label != new_label {
            note.label = new_label;
            changed = true;
        }
        if note.value != new_value {
            note.value = new_value;
            changed = true;
        }
    }
    // If the receipt is missing/malformed on a confirmed read we intentionally
    // leave the existing fields untouched and fall through; the next read will
    // try again (c6 self-heal).

    Ok(if changed {
        Reconciliation::Updated
    } else {
        Reconciliation::Unchanged
    })
}

/// As [`apply_reconciliation`] but persists the note/status when it changed.
pub fn reconcile_with(
    note: &mut StoredNote,
    wallet: &str,
    id: &str,
    inspection: &OutboxInspection,
) -> Result<(), String> {
    match apply_reconciliation(note, inspection)? {
        Reconciliation::Unchanged => Ok(()),
        Reconciliation::Updated => notes::persist_update(note, wallet, id),
    }
}

/// Parsed `Deposited` log fields.
pub struct DepositedLog {
    pub commitment: U256,
    pub label: U256,
    pub value: U256,
    pub precommitment: U256,
}

/// Find the `Deposited` event in a transaction receipt JSON and decode its
/// fields, matching only logs emitted by the canonical mainnet pool or
/// entrypoint.
pub fn parse_deposited(receipt_json: &str) -> Option<DepositedLog> {
    parse_deposited_in(receipt_json, &[POOL_ETH, ENTRYPOINT])
}

/// As [`parse_deposited`] but with a caller-supplied emitter allow-list, so
/// the parser is reusable against non-mainnet deployments (tests, local anvil,
/// future migrated pool addresses).
pub fn parse_deposited_in(
    receipt_json: &str,
    emitters: &[alloy_primitives::Address],
) -> Option<DepositedLog> {
    let v: serde_json::Value = serde_json::from_str(receipt_json).ok()?;
    let topic0 = format!("0x{}", hex::encode(deposited_topic0()));
    let allowed: Vec<String> = emitters
        .iter()
        .map(|a| format!("{a:?}").to_ascii_lowercase())
        .collect();
    let emitter_ok = |addr: &str| {
        let a = addr.strip_prefix("0x").unwrap_or(addr).to_ascii_lowercase();
        allowed.contains(&format!("0x{a}"))
    };
    let logs = v.get("logs")?.as_array()?;
    for log in logs {
        let topics = log.get("topics")?.as_array()?;
        if topics.is_empty() {
            continue;
        }
        if topics.first().and_then(|t| t.as_str()) != Some(&topic0) {
            continue;
        }
        // Emitter allow-list (c3). If an allow-list was supplied, only logs
        // from those contracts match; an empty allow-list accepts any emitter.
        if !allowed.is_empty()
            && let Some(addr) = log.get("address").and_then(|a| a.as_str())
            && !emitter_ok(addr)
        {
            continue;
        }
        let data = log.get("data")?.as_str()?;
        let bytes = hex::decode(data.strip_prefix("0x").unwrap_or(data)).ok()?;
        if bytes.len() < 128 {
            return None;
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes[..32]);
        let commitment = U256::from_be_bytes(buf);
        buf.copy_from_slice(&bytes[32..64]);
        let label = U256::from_be_bytes(buf);
        buf.copy_from_slice(&bytes[64..96]);
        let value = U256::from_be_bytes(buf);
        buf.copy_from_slice(&bytes[96..128]);
        let precommitment = U256::from_be_bytes(buf);
        return Some(DepositedLog {
            commitment,
            label,
            value,
            precommitment,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::commitment_hash;
    use crate::types::TxRef;
    use alloy_primitives::U256;

    fn amt(wei: u64) -> U256 {
        U256::from(wei)
    }

    fn note_with(status: &str, amount: U256) -> StoredNote {
        StoredNote {
            wallet: "w".into(),
            asset: "eth".into(),
            amount_wei: amount.to_string(),
            nullifier: "0x1".into(),
            secret: "0x2".into(),
            precommitment: "0x3".into(),
            status: status.into(),
            tx: TxRef {
                chain: CHAIN.into(),
                outbox_id: String::new(),
                tx_hash: None,
            },
            value: None,
            label: None,
            commitment: None,
            spent: false,
            approval_action_id: None,
            approval_ceremony_url: None,
            approval_expires_ms: None,
        }
    }

    #[test]
    fn calldata_is_selector_plus_single_word() {
        let pre = U256::from(0xabc);
        let data = build_eth_deposit_calldata(pre);
        assert_eq!(data.len(), 36);
        assert_eq!(&data[0..4], &deposit_eth_selector());
        // last 32 bytes == big-endian precommitment
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&data[4..]);
        assert_eq!(U256::from_be_bytes(buf), pre);
    }

    #[test]
    fn validate_amount_rejects_non_decimal_and_zero() {
        assert!(validate_amount("1000000000000000000").is_ok());
        assert!(validate_amount("0").is_err());
        assert!(validate_amount("0x1").is_err());
        assert!(validate_amount("").is_err());
    }

    // ---- c2: classify_existing idempotency policy ----

    #[test]
    fn classify_new_when_absent() {
        assert_eq!(classify_existing(None, amt(1)), CreateAttempt::NewDeposit);
    }

    #[test]
    fn classify_conflict_on_different_amount() {
        let n = note_with("staged", amt(1));
        assert_eq!(classify_existing(Some(&n), amt(2)), CreateAttempt::Conflict);
    }

    #[test]
    fn classify_incomplete_while_staging() {
        // Placeholder written before stage; outcome uncertain → never re-stage.
        let n = note_with("staging", amt(1));
        assert_eq!(
            classify_existing(Some(&n), amt(1)),
            CreateAttempt::Incomplete
        );
    }

    #[test]
    fn classify_new_after_definitive_stage_failure() {
        // stage-failed is recoverable with the same id.
        let n = note_with("stage-failed", amt(1));
        assert_eq!(
            classify_existing(Some(&n), amt(1)),
            CreateAttempt::NewDeposit
        );
    }

    #[test]
    fn classify_retry_for_terminal_states() {
        for status in [
            "staged",
            "confirmed",
            "failed",
            "reverted",
            "unknown-future",
        ] {
            let n = note_with(status, amt(7));
            assert_eq!(
                classify_existing(Some(&n), amt(7)),
                CreateAttempt::Retry,
                "status={status}"
            );
        }
    }

    // ---- c3: address filter ----

    fn receipt_with_log(
        emitter: &str,
        commitment: U256,
        label: U256,
        value: U256,
        precommitment: U256,
    ) -> String {
        // Real event layout (IPrivacyPool.sol:39): only _depositor is indexed.
        // topics = [topic0, _depositor]; data = abi.encode(commitment, label,
        // value, precommitment) = 128 bytes.
        let topic0 = format!("0x{}", hex::encode(deposited_topic0()));
        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(&commitment.to_be_bytes::<32>());
        data.extend_from_slice(&label.to_be_bytes::<32>());
        data.extend_from_slice(&value.to_be_bytes::<32>());
        data.extend_from_slice(&precommitment.to_be_bytes::<32>());
        serde_json::json!({
            "logs": [{
                "address": emitter,
                "topics": [topic0, format!("0x{:064x}", U256::ZERO)],
                "data": format!("0x{}", hex::encode(&data)),
            }]
        })
        .to_string()
    }

    #[test]
    fn parse_deposited_decodes_indexed_and_data_fields() {
        let commitment = U256::from(1);
        let label = U256::from(2);
        let value = U256::from(7);
        let precommitment = U256::from(3);
        let receipt = receipt_with_log(
            "0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb", // POOL_ETH
            commitment,
            label,
            value,
            precommitment,
        );
        let parsed = parse_deposited(&receipt).expect("parses");
        assert_eq!(parsed.commitment, commitment);
        assert_eq!(parsed.label, label);
        assert_eq!(parsed.value, value);
        assert_eq!(parsed.precommitment, precommitment);
    }

    #[test]
    fn parse_deposited_ignores_unrelated_logs() {
        let receipt = serde_json::json!({
            "logs": [{
                "topics": ["0xdeadbeef".to_string()],
                "data": "0x",
            }]
        })
        .to_string();
        assert!(parse_deposited(&receipt).is_none());
    }

    #[test]
    fn parse_deposited_rejects_wrong_emitter_and_accepts_known_one() {
        let commitment = U256::from(1);
        let label = U256::from(2);
        let value = U256::from(7);
        let precommitment = U256::from(3);
        // A same-topic0 log from an unrelated contract must be ignored.
        let wrong = receipt_with_log(
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            commitment,
            label,
            value,
            precommitment,
        );
        assert!(
            parse_deposited(&wrong).is_none(),
            "wrong emitter must be filtered"
        );

        // The entrypoint is also an accepted emitter (case-insensitive).
        let upper = receipt_with_log(
            "0x6818809EEFCE719E480A7526D76BD3E561526B46",
            commitment,
            label,
            value,
            precommitment,
        );
        assert!(
            parse_deposited(&upper).is_some(),
            "entrypoint emitter (uppercase) accepted"
        );

        // If a wrong-emitter log precedes the real one, the real one is found.
        // Both logs use the canonical 2-topic / 128-byte-data layout.
        let topic0 = format!("0x{}", hex::encode(deposited_topic0()));
        let mut real_data = Vec::with_capacity(128);
        real_data.extend_from_slice(&commitment.to_be_bytes::<32>());
        real_data.extend_from_slice(&label.to_be_bytes::<32>());
        real_data.extend_from_slice(&value.to_be_bytes::<32>());
        real_data.extend_from_slice(&precommitment.to_be_bytes::<32>());
        let combined = serde_json::json!({
            "logs": [
                {
                    "address": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "topics": [topic0.clone(), format!("0x{:064x}", U256::ZERO)],
                    "data": format!("0x{}", hex::encode(&real_data)),
                },
                {
                    "address": "0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb",
                    "topics": [topic0, format!("0x{:064x}", U256::ZERO)],
                    "data": format!("0x{}", hex::encode(&real_data)),
                },
            ]
        })
        .to_string();
        let parsed = parse_deposited(&combined).expect("finds the real emitter");
        assert_eq!(parsed.commitment, commitment);
        assert_eq!(parsed.label, label);
        assert_eq!(parsed.value, value);
        assert_eq!(parsed.precommitment, precommitment);
    }

    // ---- c6 + c9: apply_reconciliation ----

    fn inspection(state: &str, receipt: Option<&str>) -> OutboxInspection {
        OutboxInspection {
            outbox_id: "ob-1".into(),
            state: state.into(),
            tx_hash: Some("0xabc".into()),
            receipt_json: receipt.map(|s| s.to_string()),
        }
    }

    fn good_receipt_for(note: &StoredNote, value: U256, label: U256) -> String {
        // Build a receipt whose commitment is the canonical
        // poseidon([value, label, precommitment]) for this note.
        let pre = U256::from_str_radix(note.precommitment.trim_start_matches("0x"), 16).unwrap();
        let commitment = commitment_hash(value, label, pre);
        receipt_with_log(
            "0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb",
            commitment,
            label,
            value,
            pre,
        )
    }

    #[test]
    fn reconcile_fills_fields_on_confirmed_and_persists_change() {
        let mut n = note_with("staged", amt(1));
        let value = U256::from(1_000_000_000_000_000_000u128);
        let label = U256::from(0x42);
        let receipt = good_receipt_for(&n, value, label);
        let outcome = apply_reconciliation(&mut n, &inspection("confirmed", Some(&receipt)));
        assert_eq!(outcome.unwrap(), Reconciliation::Updated);
        assert_eq!(n.status, "confirmed");
        assert!(n.commitment.is_some());
        assert!(n.label.is_some());
        assert_eq!(n.value.as_deref(), Some(value.to_string().as_str()));
    }

    #[test]
    fn reconcile_self_heals_after_malformed_receipt() {
        // c6: a confirmed read with a malformed receipt must NOT permanently
        // corrupt the note. The fields stay empty and a later good receipt
        // fills them in.
        let mut n = note_with("staged", amt(1));
        let malformed = serde_json::json!({ "logs": [] }).to_string();
        let first = apply_reconciliation(&mut n, &inspection("confirmed", Some(&malformed)));
        assert_eq!(first.unwrap(), Reconciliation::Updated); // status changed staged→confirmed
        assert!(
            n.commitment.is_none(),
            "malformed receipt must not fill commitment"
        );

        let value = U256::from(5);
        let label = U256::from(0x11);
        let good = good_receipt_for(&n, value, label);
        let second = apply_reconciliation(&mut n, &inspection("confirmed", Some(&good)));
        assert_eq!(second.unwrap(), Reconciliation::Updated);
        assert!(n.commitment.is_some(), "self-heal on the second read");
    }

    #[test]
    fn reconcile_is_idempotent_when_unchanged() {
        // After a successful fill, re-running with the same receipt reports
        // Unchanged (so the store is not thrashed on every read).
        let mut n = note_with("staged", amt(1));
        let value = U256::from(5);
        let label = U256::from(0x11);
        let receipt = good_receipt_for(&n, value, label);
        apply_reconciliation(&mut n, &inspection("confirmed", Some(&receipt))).unwrap();
        let again = apply_reconciliation(&mut n, &inspection("confirmed", Some(&receipt)));
        assert_eq!(again.unwrap(), Reconciliation::Unchanged);
    }

    #[test]
    fn reconcile_rejects_tampered_commitment() {
        // c9: the emitted commitment must equal poseidon([value,label,pre]).
        let mut n = note_with("staged", amt(1));
        let value = U256::from(5);
        let label = U256::from(0x11);
        let pre = U256::from_str_radix(n.precommitment.trim_start_matches("0x"), 16).unwrap();
        // Deliberately wrong commitment (does not equal the recomputed hash).
        let tampered = receipt_with_log(
            "0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb",
            U256::from(0xbad),
            label,
            value,
            pre,
        );
        let err = apply_reconciliation(&mut n, &inspection("confirmed", Some(&tampered)));
        assert!(err.is_err(), "tampered commitment must be rejected");
    }

    #[test]
    fn reconcile_rejects_precommitment_mismatch() {
        // A receipt whose precommitment is not this note's must be rejected.
        let mut n = note_with("staged", amt(1));
        let value = U256::from(5);
        let label = U256::from(0x11);
        let stranger = U256::from(0xdead);
        let commitment = commitment_hash(value, label, stranger);
        let receipt = receipt_with_log(
            "0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb",
            commitment,
            label,
            value,
            stranger,
        );
        let err = apply_reconciliation(&mut n, &inspection("confirmed", Some(&receipt)));
        assert!(err.is_err(), "foreign precommitment must be rejected");
    }

    #[test]
    fn reconcile_maps_failure_states() {
        let mut n = note_with("staged", amt(1));
        for raw in ["failed", "reverted"] {
            n.status = "staged".into();
            let outcome = apply_reconciliation(&mut n, &inspection(raw, None));
            assert_eq!(outcome.unwrap(), Reconciliation::Updated);
            assert_eq!(n.status, "failed", "raw={raw}");
        }
    }
}
