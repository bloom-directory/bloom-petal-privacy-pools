//! Direct Privacy Pools withdrawal preparation, staging, and reconciliation.
//!
//! Groth16 proving remains in the local companion tool. This module never
//! exports note secrets: it validates the tool's exact calldata against the
//! private note and replacement record, checks live roots/unspent state,
//! simulates, stages through Bloom's outbox, and reconciles settlement.

use alloy_primitives::{Address, U256};
use petal::{DispatchResponse, EvmTransaction, HostStatus, sdk};
use serde_json::Value;
use sha3::{Digest, Keccak256};

use crate::commitment::{commitment_hash, precommitment_hash};
use crate::field::FIELD_P;
use crate::notes;
use crate::protocol::{CHAIN, POOL_ETH};
use crate::types::{
    DepositStatus, PrivateRelayRequest, PrivateRelayStatus, ReplacementNote, StoredNote, TxRef,
    WithdrawalRequest, WithdrawalStatus,
};

const MAX_REQUEST_BYTES: usize = 32 * 1024;
const DIRECT_WORDS: usize = 20;
const WITHDRAWAL_PUBLIC_SIGNALS_START: usize = 9;

fn err(code: i32, msg: impl Into<String>) -> DispatchResponse {
    petal::error(code, msg)
}

fn parse_u256(value: &str, label: &str) -> Result<U256, String> {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        U256::from_str_radix(hex, 16).map_err(|_| format!("{label} is not valid hex"))
    } else {
        U256::from_str_radix(value, 10).map_err(|_| format!("{label} is not decimal"))
    }
}

fn as_hex(value: U256) -> String {
    format!("0x{:064x}", value)
}

fn calldata_hash(data: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    format!("0x{}", hex::encode(hasher.finalize()))
}

fn word(data: &[u8], index: usize) -> Result<U256, String> {
    let start = 4 + index * 32;
    let end = start + 32;
    if end > data.len() {
        return Err("withdraw calldata is truncated".into());
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&data[start..end]);
    Ok(U256::from_be_bytes(bytes))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectWithdrawalCall {
    pub processooor: Address,
    pub public_signals: [U256; 8],
}

/// Decode the one supported submission shape: a direct withdrawal with empty
/// `withdrawal.data`. Rejecting alternate ABI shapes keeps validation strict.
pub fn decode_direct_calldata(data: &[u8]) -> Result<DirectWithdrawalCall, String> {
    if data.len() != 4 + DIRECT_WORDS * 32 {
        return Err(format!(
            "direct withdrawal calldata must be {} bytes, got {}",
            4 + DIRECT_WORDS * 32,
            data.len()
        ));
    }
    if data[..4] != crate::protocol::withdraw_selector() {
        return Err("calldata is not PrivacyPool.withdraw".into());
    }
    if word(data, 0)? != U256::from(17 * 32) {
        return Err("unexpected withdrawal tuple offset".into());
    }
    if word(data, 18)? != U256::from(64) || word(data, 19)? != U256::ZERO {
        return Err("only direct withdrawals with empty data are supported".into());
    }
    let address_word = word(data, 17)?.to_be_bytes::<32>();
    if address_word[..12].iter().any(|byte| *byte != 0) {
        return Err("processooor address is not canonically encoded".into());
    }
    let processooor = Address::from_slice(&address_word[12..]);
    let mut public_signals = [U256::ZERO; 8];
    for (offset, signal) in public_signals.iter_mut().enumerate() {
        *signal = word(data, WITHDRAWAL_PUBLIC_SIGNALS_START + offset)?;
    }
    Ok(DirectWithdrawalCall {
        processooor,
        public_signals,
    })
}

/// `abi.encode((address processooor, bytes data), uint256 scope)`.
pub fn encode_context(processooor: Address, data: &[u8], scope: U256) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&U256::from(64u64).to_be_bytes::<32>());
    out.extend_from_slice(&scope.to_be_bytes::<32>());
    let mut addr = [0u8; 32];
    addr[12..].copy_from_slice(processooor.as_ref());
    out.extend_from_slice(&addr);
    out.extend_from_slice(&U256::from(64u64).to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(data.len() as u64).to_be_bytes::<32>());
    out.extend_from_slice(data);
    while out.len() % 32 != 0 {
        out.push(0);
    }
    out
}

pub fn context_hash(processooor: Address, data: &[u8], scope: U256) -> U256 {
    let mut hasher = Keccak256::new();
    hasher.update(encode_context(processooor, data, scope));
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hasher.finalize());
    U256::from_be_bytes(bytes) % FIELD_P
}

fn wallet_address(wallet: &str) -> Result<Address, String> {
    let bytes =
        sdk::vfs_read(&format!("wallets/{wallet}/address"), 128).map_err(|e| e.message())?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| "wallet address is not UTF-8")?
        .trim();
    value
        .parse()
        .map_err(|_| "wallet is not a 20-byte EVM address".into())
}

fn preview_next(unspent: bool, backup_verified: bool) -> &'static str {
    if !unspent {
        "This note is already spent on-chain; do not generate or stage another withdrawal."
    } else if !backup_verified {
        "Create and verify an encrypted note backup with tools/privacy-pools backup before proving."
    } else {
        "Run tools/privacy-pools prepare, then write its public stage request back to this path. Context remains null until the real signing wallet/processooor is selected."
    }
}

fn validate_replacement(
    replacement: &ReplacementNote,
    note_wallet: &str,
    note_id: &str,
    note: &StoredNote,
    call: &DirectWithdrawalCall,
    call_hash: &str,
) -> Result<U256, String> {
    if replacement.parent_wallet != note_wallet || replacement.parent_id != note_id {
        return Err("replacement note belongs to a different parent deposit".into());
    }
    if !replacement.backup_verified {
        return Err("replacement note backup has not been verified".into());
    }
    if !replacement.calldata_hash.eq_ignore_ascii_case(call_hash) {
        return Err("replacement note is not bound to this calldata".into());
    }
    let existing_value = parse_u256(
        note.value.as_deref().ok_or("deposit is missing value")?,
        "existing value",
    )?;
    let withdrawn_value = call.public_signals[2];
    if withdrawn_value == U256::ZERO || withdrawn_value > existing_value {
        return Err("withdrawn value must be non-zero and no greater than the note value".into());
    }
    let remaining = existing_value - withdrawn_value;
    if parse_u256(&replacement.remaining_value, "replacement remaining value")? != remaining {
        return Err("replacement remaining value does not match proof".into());
    }
    let label = parse_u256(
        note.label.as_deref().ok_or("deposit is missing label")?,
        "label",
    )?;
    if parse_u256(&replacement.label, "replacement label")? != label {
        return Err("replacement label does not match the existing note".into());
    }
    let nullifier = parse_u256(&replacement.nullifier, "replacement nullifier")?;
    let secret = parse_u256(&replacement.secret, "replacement secret")?;
    let expected = commitment_hash(remaining, label, precommitment_hash(nullifier, secret));
    if expected != call.public_signals[0]
        || parse_u256(&replacement.new_commitment, "replacement commitment")? != expected
    {
        return Err("replacement secrets do not reproduce the proof commitment".into());
    }
    Ok(remaining)
}

fn preview(wallet: &str, id: &str) -> DispatchResponse {
    let mut note = match notes::load_note(wallet, id) {
        Ok(Some(note)) => note,
        Ok(None) => return err(-1, "no such deposit"),
        Err(e) => return err(-4, e),
    };
    if !note.tx.outbox_id.is_empty()
        && let Err(e) = crate::deposit::reconcile(&mut note, wallet, id)
    {
        return err(-4, e);
    }
    let Some(commitment) = note.commitment.clone() else {
        return err(-3, "deposit is not fully reconciled: missing commitment");
    };
    let Some(label) = note.label.clone() else {
        return err(-3, "deposit is not fully reconciled: missing label");
    };
    let Some(value) = note.value.clone() else {
        return err(-3, "deposit is not fully reconciled: missing value");
    };

    let asp_root = crate::chain::latest_asp_root().ok();
    let state_root = crate::chain::current_root(POOL_ETH).ok();
    let state_depth = crate::chain::current_tree_depth(POOL_ETH).ok();
    let tree_size = crate::chain::current_tree_size(POOL_ETH).ok();
    let scope = crate::chain::pool_scope(POOL_ETH).ok();
    let unspent = !note.spent;
    let next = preview_next(unspent, note.backup_verified);

    petal::read_json_value(&serde_json::json!({
        "petal": "privacy-pools",
        "kind": "withdrawal-readiness",
        "chain": CHAIN,
        "pool": format!("{POOL_ETH:?}"),
        "asset": note.asset,
        "note": {
            "commitment": commitment,
            "label": label,
            "value": value,
            "precommitment": note.precommitment,
            "backup_verified": note.backup_verified,
        },
        "roots": {
            "asp_root": asp_root.map(as_hex),
            "state_root": state_root.map(as_hex),
            "state_tree_depth": state_depth.map(|value| value.to_string()),
            "state_tree_size": tree_size.map(|value| value.to_string()),
            "scope": scope.map(as_hex),
        },
        "withdrawal_proof_input": {
            "public_signals": {
                "withdrawnValue": value,
                "stateRoot": null,
                "stateTreeDepth": null,
                "ASPRoot": asp_root.map(as_hex),
                "ASPTreeDepth": null,
                "context": null,
            },
            "private_signals": {
                "label": label,
                "existingValue": value,
                "existingNullifier": null,
                "existingSecret": null,
                "newNullifier": null,
                "newSecret": null,
            },
            "merkle_proofs": {
                "stateSiblings": null,
                "stateIndex": null,
                "ASPSiblings": null,
                "ASPIndex": null,
            }
        },
        "readiness": {
            "public_metadata_reconciled": true,
            "secret_note_available": true,
            "backup_verified": note.backup_verified,
            "unspent_verified_onchain": unspent,
            "state_inclusion_verified": false,
            "asp_inclusion_verified": false,
            "proof_generated": false,
            "proof_verified": false,
            "call_simulated": false,
            "transaction_staged": false,
            "settlement_verified": false,
        },
        "next": next
    }))
}

pub fn read(wallet: &str, id: &str) -> DispatchResponse {
    if let Err(e) = notes::validate_idents(wallet, id) {
        return err(-3, e);
    }
    match notes::load_private_relay(wallet, id) {
        Ok(Some(status)) => return petal::read_json_value(&status),
        Ok(None) => {}
        Err(e) => return err(-4, e),
    }
    match notes::load_withdrawal(wallet, id) {
        Ok(Some(mut status)) => {
            if let Err(e) = reconcile(&mut status) {
                return err(-4, e);
            }
            petal::read_json_value(&status)
        }
        Ok(None) => preview(wallet, id),
        Err(e) => err(-4, e),
    }
}

pub fn stage(wallet: &str, id: &str, body: &[u8]) -> DispatchResponse {
    if let Err(e) = notes::validate_idents(wallet, id) {
        return err(-3, e);
    }
    if body.len() > MAX_REQUEST_BYTES {
        return err(-3, "withdrawal request body is too large");
    }
    let body_json: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(e) => return err(-3, format!("invalid withdrawal request JSON: {e}")),
    };
    if body_json.get("mode").and_then(Value::as_str) == Some("private-relay") {
        let request: PrivateRelayRequest = match serde_json::from_value(body_json) {
            Ok(request) => request,
            Err(e) => return err(-3, format!("invalid private relay request JSON: {e}")),
        };
        return stage_private_relay(wallet, id, request);
    }
    let request: WithdrawalRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(e) => return err(-3, format!("invalid withdrawal request JSON: {e}")),
    };
    if let Err(e) = notes::validate_idents(&request.signing_wallet, &request.replacement_id) {
        return err(-3, e);
    }

    let Some(encoded_calldata) = request.calldata.strip_prefix("0x") else {
        return err(-3, "calldata must be 0x-prefixed");
    };
    let data = match hex::decode(encoded_calldata) {
        Ok(data) => data,
        Err(e) => return err(-3, format!("calldata hex: {e}")),
    };
    let call = match decode_direct_calldata(&data) {
        Ok(call) => call,
        Err(e) => return err(-3, e),
    };
    let hash = calldata_hash(&data);

    let retry_after_stage_failure = match notes::load_withdrawal(wallet, id) {
        Ok(Some(existing))
            if existing.calldata_hash.eq_ignore_ascii_case(&hash)
                && existing.status == "stage-failed" =>
        {
            true
        }
        Ok(Some(existing)) if existing.calldata_hash.eq_ignore_ascii_case(&hash) => {
            return DispatchResponse::Write;
        }
        Ok(Some(_)) => return err(-3, "a different withdrawal already exists for this note"),
        Ok(None) => false,
        Err(e) => return err(-4, e),
    };

    let mut note = match notes::load_note(wallet, id) {
        Ok(Some(note)) => note,
        Ok(None) => return err(-1, "no such deposit"),
        Err(e) => return err(-4, e),
    };
    if let Err(e) = crate::deposit::reconcile(&mut note, wallet, id) {
        return err(-4, e);
    }
    if note.spent {
        return err(-3, "note nullifier is already spent on-chain");
    }
    if !note.backup_verified {
        return err(
            -3,
            "note backup has not been verified; run the local backup tool first",
        );
    }
    let expected_processooor = match wallet_address(&request.signing_wallet) {
        Ok(address) => address,
        Err(e) => return err(-4, e),
    };
    if call.processooor != expected_processooor {
        return err(
            -3,
            "calldata processooor does not match the signing wallet address",
        );
    }
    let existing_nullifier = match parse_u256(&note.nullifier, "stored nullifier") {
        Ok(value) => value,
        Err(e) => return err(-4, e),
    };
    let existing_nullifier_hash = crate::poseidon::hash1(existing_nullifier);
    if call.public_signals[1] != existing_nullifier_hash {
        return err(-3, "proof nullifier hash does not match the private note");
    }
    let scope = match crate::chain::pool_scope(POOL_ETH) {
        Ok(scope) => scope,
        Err(e) => return err(-4, e),
    };
    if call.public_signals[7] != context_hash(call.processooor, &[], scope) {
        return err(
            -3,
            "proof context does not match processooor and pool scope",
        );
    }
    let latest_asp_root = match crate::chain::latest_asp_root() {
        Ok(root) => root,
        Err(e) => return err(-4, e),
    };
    if call.public_signals[5] != latest_asp_root {
        return err(-3, "proof ASP root is stale; regenerate the proof");
    }
    let replacement = match notes::load_replacement(wallet, &request.replacement_id) {
        Ok(Some(replacement)) => replacement,
        Ok(None) => return err(-3, "replacement note is missing from the private store"),
        Err(e) => return err(-4, e),
    };
    if replacement.replacement_id != request.replacement_id {
        return err(-3, "replacement id does not match its private record");
    }
    if let Err(e) = validate_replacement(&replacement, wallet, id, &note, &call, &hash) {
        return err(-3, e);
    }
    if let Err(e) =
        crate::chain::eth_call_from(call.processooor, POOL_ETH, &data, "withdraw simulation")
    {
        return err(-3, format!("exact withdrawal simulation failed: {e}"));
    }

    let mut status = WithdrawalStatus {
        note_wallet: wallet.to_string(),
        note_id: id.to_string(),
        signing_wallet: request.signing_wallet.clone(),
        processooor: format!("{:?}", call.processooor),
        withdrawal_value_wei: call.public_signals[2].to_string(),
        existing_nullifier_hash: as_hex(call.public_signals[1]),
        new_commitment: as_hex(call.public_signals[0]),
        state_root: as_hex(call.public_signals[3]),
        asp_root: as_hex(call.public_signals[5]),
        replacement_id: request.replacement_id,
        calldata_hash: hash,
        status: "staging".into(),
        tx: TxRef {
            chain: CHAIN.into(),
            outbox_id: String::new(),
            tx_hash: None,
        },
        approval_action_id: None,
        approval_expires_ms: None,
        settlement_verified: false,
    };
    let claim = if retry_after_stage_failure {
        notes::store_withdrawal(&status)
    } else {
        notes::store_withdrawal_new(&status)
    };
    if let Err(e) = claim {
        return err(-3, format!("could not claim withdrawal id: {e}"));
    }

    let staged = match sdk::tx_stage(&EvmTransaction {
        wallet: request.signing_wallet,
        chain: CHAIN.into(),
        to: format!("{POOL_ETH:?}"),
        value_wei: "0".into(),
        data_hex: request.calldata,
        nonce: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    }) {
        Ok(staged) => staged,
        Err(petal::SdkError::Host(HostStatus::Denied)) => {
            status.status = "stage-failed".into();
            let _ = notes::store_withdrawal(&status);
            return err(-2, "withdrawal staging was denied by the host");
        }
        Err(e) => {
            status.status = "stage-failed".into();
            let _ = notes::store_withdrawal(&status);
            return err(-4, format!("failed to stage withdrawal: {}", e.message()));
        }
    };
    status.status = "staged".into();
    status.tx.outbox_id = staged.outbox_id;
    status.approval_action_id = staged
        .approval
        .as_ref()
        .map(|value| value.action_id.clone());
    status.approval_expires_ms = staged.approval.as_ref().map(|value| value.expires_ms);
    if let Err(e) = notes::store_withdrawal(&status) {
        return err(
            -4,
            format!("withdrawal staged but status persistence failed: {e}"),
        );
    }
    DispatchResponse::Write
}

fn stage_private_relay(wallet: &str, id: &str, request: PrivateRelayRequest) -> DispatchResponse {
    if request.mode != "private-relay" {
        return err(-3, "private relay mode must be private-relay");
    }
    if let Err(e) = notes::validate_idents(wallet, &request.replacement_id) {
        return err(-3, e);
    }
    if request.replacement_id == id {
        return err(-3, "replacement id must differ from the existing note id");
    }
    if let Some(amount) = &request.amount_wei
        && (amount.is_empty() || !amount.bytes().all(|byte| byte.is_ascii_digit()) || amount == "0")
    {
        return err(-3, "amount_wei must be a non-zero decimal integer");
    }
    match notes::load_private_relay(wallet, id) {
        Ok(Some(status)) => {
            if status.replacement_id != request.replacement_id
                || status.amount_wei != request.amount_wei
            {
                return err(
                    -3,
                    "a different private relay request already exists for this note",
                );
            }
            return DispatchResponse::Write;
        }
        Ok(None) => {}
        Err(e) => return err(-4, e),
    }
    let mut note = match notes::load_note(wallet, id) {
        Ok(Some(note)) => note,
        Ok(None) => return err(-1, "no such deposit"),
        Err(e) => return err(-4, e),
    };
    if let Err(e) = crate::deposit::reconcile(&mut note, wallet, id) {
        return err(-4, e);
    }
    if note.spent {
        return err(-3, "note nullifier is already spent on-chain");
    }
    if !note.backup_verified {
        return err(
            -3,
            "note backup has not been verified; run the local backup tool first",
        );
    }
    if note.commitment.is_none() || note.label.is_none() || note.value.is_none() {
        return err(-3, "deposit is not fully reconciled");
    }
    let note_value = match parse_u256(note.value.as_deref().expect("checked above"), "note value") {
        Ok(value) => value,
        Err(e) => return err(-4, e),
    };
    if let Some(amount) = request.amount_wei.as_deref() {
        let amount = match parse_u256(amount, "amount_wei") {
            Ok(value) => value,
            Err(e) => return err(-3, e),
        };
        if amount > note_value {
            return err(-3, "amount_wei exceeds the note value");
        }
    }
    let status = PrivateRelayStatus {
            note_wallet: wallet.into(),
            note_id: id.into(),
            replacement_id: request.replacement_id,
            amount_wei: request.amount_wei,
            status: "awaiting-owner-input".into(),
            next: "Run tools/privacy-pools relay-private for this note; it opens a local browser form for the destination.".into(),
    };
    if let Err(e) = notes::store_private_relay_new(&status) {
        return err(-4, e);
    }
    DispatchResponse::Write
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WithdrawnEvent {
    processooor: Address,
    value: U256,
    spent_nullifier: U256,
    new_commitment: U256,
}

fn parse_withdrawn(receipt: &str) -> Option<WithdrawnEvent> {
    let value: Value = serde_json::from_str(receipt).ok()?;
    let logs = value.get("logs")?.as_array()?;
    for log in logs {
        let address = log.get("address")?.as_str()?;
        if !address.eq_ignore_ascii_case(&format!("{POOL_ETH:?}")) {
            continue;
        }
        let topics = log.get("topics")?.as_array()?;
        if topics.len() < 2
            || topics[0].as_str()?.trim_start_matches("0x")
                != hex::encode(crate::protocol::withdrawn_topic0())
        {
            continue;
        }
        let processooor_word = hex::decode(topics[1].as_str()?.trim_start_matches("0x")).ok()?;
        if processooor_word.len() != 32 {
            continue;
        }
        let processooor = Address::from_slice(&processooor_word[12..]);
        let data = hex::decode(log.get("data")?.as_str()?.trim_start_matches("0x")).ok()?;
        if data.len() != 96 {
            continue;
        }
        let mut values = [U256::ZERO; 3];
        for (index, item) in values.iter_mut().enumerate() {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data[index * 32..(index + 1) * 32]);
            *item = U256::from_be_bytes(bytes);
        }
        return Some(WithdrawnEvent {
            processooor,
            value: values[0],
            spent_nullifier: values[1],
            new_commitment: values[2],
        });
    }
    None
}

fn promote_replacement(
    status: &WithdrawalStatus,
    replacement: &ReplacementNote,
) -> Result<(), String> {
    let remaining = parse_u256(&replacement.remaining_value, "replacement remaining value")?;
    if remaining == U256::ZERO {
        return Ok(());
    }
    let nullifier = parse_u256(&replacement.nullifier, "replacement nullifier")?;
    let secret = parse_u256(&replacement.secret, "replacement secret")?;
    let precommitment = precommitment_hash(nullifier, secret);
    let promoted = StoredNote {
        wallet: status.note_wallet.clone(),
        asset: "eth".into(),
        amount_wei: remaining.to_string(),
        nullifier: replacement.nullifier.clone(),
        secret: replacement.secret.clone(),
        precommitment: as_hex(precommitment),
        status: "confirmed".into(),
        tx: status.tx.clone(),
        value: Some(remaining.to_string()),
        label: Some(replacement.label.clone()),
        commitment: Some(replacement.new_commitment.clone()),
        spent: false,
        backup_verified: replacement.backup_verified,
        approval_action_id: None,
        approval_expires_ms: None,
    };
    match notes::load_note(&status.note_wallet, &status.replacement_id)? {
        Some(existing) if existing.commitment == promoted.commitment => Ok(()),
        Some(_) => Err("replacement id already belongs to a different note".into()),
        None => {
            notes::store_note_by_id(&promoted, &status.note_wallet, &status.replacement_id)?;
            notes::store_status(
                &DepositStatus::from(&promoted),
                &status.note_wallet,
                &status.replacement_id,
            )
        }
    }
}

fn reconcile(status: &mut WithdrawalStatus) -> Result<(), String> {
    if status.settlement_verified || status.tx.outbox_id.is_empty() {
        return Ok(());
    }
    let inspection = sdk::tx_inspect(&status.signing_wallet, CHAIN, &status.tx.outbox_id)
        .map_err(|e| e.message())?;
    status.tx.tx_hash = inspection.tx_hash.clone();
    match inspection.state.as_str() {
        "failed" | "reverted" => {
            status.status = "failed".into();
            return notes::store_withdrawal(status);
        }
        "confirmed" | "mined" | "success" => {}
        other => {
            status.status = other.into();
            return notes::store_withdrawal(status);
        }
    }
    let receipt = inspection
        .receipt_json
        .filter(|receipt| parse_withdrawn(receipt).is_some())
        .or_else(|| {
            inspection
                .tx_hash
                .as_deref()
                .and_then(|hash| crate::chain::transaction_receipt(hash).ok().flatten())
        })
        .ok_or("withdrawal mined but receipt is unavailable")?;
    let event = parse_withdrawn(&receipt).ok_or("receipt has no matching Withdrawn event")?;
    if !format!("{:?}", event.processooor).eq_ignore_ascii_case(&status.processooor)
        || event.value != parse_u256(&status.withdrawal_value_wei, "withdrawal value")?
        || event.spent_nullifier != parse_u256(&status.existing_nullifier_hash, "spent nullifier")?
        || event.new_commitment != parse_u256(&status.new_commitment, "new commitment")?
    {
        return Err("Withdrawn event does not match the staged proof".into());
    }
    if !crate::chain::nullifier_spent(POOL_ETH, event.spent_nullifier)? {
        return Err("pool does not report the withdrawn nullifier as spent".into());
    }
    let replacement = notes::load_replacement(&status.note_wallet, &status.replacement_id)?
        .ok_or("private replacement note disappeared before settlement")?;
    promote_replacement(status, &replacement)?;
    let mut note = notes::load_note(&status.note_wallet, &status.note_id)?
        .ok_or("original note disappeared before settlement")?;
    note.spent = true;
    notes::persist_update(&note, &status.note_wallet, &status.note_id)?;
    status.status = "confirmed".into();
    status.settlement_verified = true;
    notes::store_withdrawal(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_calldata(processooor: Address, signals: [U256; 8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + DIRECT_WORDS * 32);
        data.extend_from_slice(&crate::protocol::withdraw_selector());
        let mut words = [U256::ZERO; DIRECT_WORDS];
        words[0] = U256::from(17 * 32);
        for (offset, signal) in signals.into_iter().enumerate() {
            words[WITHDRAWAL_PUBLIC_SIGNALS_START + offset] = signal;
        }
        words[17] = U256::from_be_slice(processooor.as_slice());
        words[18] = U256::from(64);
        for value in words {
            data.extend_from_slice(&value.to_be_bytes::<32>());
        }
        data
    }

    #[test]
    fn context_is_field_reduced_and_processooor_bound() {
        let scope = U256::from(0x42);
        let one = context_hash(Address::ZERO, &[], scope);
        let other = context_hash(Address::repeat_byte(0x11), &[], scope);
        assert!(one < FIELD_P);
        assert_ne!(one, other);
    }

    #[test]
    fn direct_calldata_round_trips_public_signals() {
        let processooor = Address::repeat_byte(0x22);
        let signals = [
            U256::from(1),
            U256::from(2),
            U256::from(3),
            U256::from(4),
            U256::from(5),
            U256::from(6),
            U256::from(7),
            U256::from(8),
        ];
        let decoded = decode_direct_calldata(&direct_calldata(processooor, signals)).unwrap();
        assert_eq!(decoded.processooor, processooor);
        assert_eq!(decoded.public_signals, signals);
    }

    #[test]
    fn direct_calldata_rejects_nonempty_data_shape() {
        let mut data = direct_calldata(Address::ZERO, [U256::ZERO; 8]);
        let len_word = 4 + 19 * 32;
        data[len_word + 31] = 1;
        assert!(decode_direct_calldata(&data).is_err());
    }

    #[test]
    fn preview_guidance_blocks_spent_notes_before_backup_advice() {
        assert!(preview_next(false, false).contains("already spent"));
        assert!(preview_next(true, false).contains("backup"));
        assert!(preview_next(true, true).contains("prepare"));
    }

    #[test]
    fn parses_real_withdrawn_event_shape() {
        let processooor = Address::repeat_byte(0x33);
        let topic_address = format!("0x{:064x}", U256::from_be_slice(processooor.as_slice()));
        let event = serde_json::json!({
            "logs": [{
                "address": format!("{POOL_ETH:?}"),
                "topics": [
                    format!("0x{}", hex::encode(crate::protocol::withdrawn_topic0())),
                    topic_address
                ],
                "data": format!("0x{:064x}{:064x}{:064x}", U256::from(1), U256::from(2), U256::from(3))
            }]
        });
        let parsed = parse_withdrawn(&event.to_string()).unwrap();
        assert_eq!(parsed.processooor, processooor);
        assert_eq!(parsed.value, U256::from(1));
        assert_eq!(parsed.spent_nullifier, U256::from(2));
        assert_eq!(parsed.new_commitment, U256::from(3));
    }
}
