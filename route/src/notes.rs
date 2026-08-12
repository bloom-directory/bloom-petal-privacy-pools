//! Private note + public status persistence through Bloom's `bloom:store`.
//!
//! Notes (with `nullifier`/`secret`) live in the **secrets** namespace; public
//! deposit status lives in the **state** namespace. Keys are namespaced under
//! `privacy-pools/...` so they never collide with another petal.

use petal::sdk;

use crate::types::{
    DepositStatus, NoteView, PrivateRelayRecipient, PrivateRelayStatus, ReplacementNote,
    StoredNote, WithdrawalStatus,
};

const MAX_NOTE_BYTES: usize = 8 * 1024;

fn check_segment(name: &str, value: &str) -> Result<(), String> {
    if petal::is_safe_segment(value) && value.len() <= 128 {
        Ok(())
    } else {
        Err(format!(
            "invalid {name}: must be a safe segment up to 128 chars"
        ))
    }
}

pub fn validate_idents(wallet: &str, id: &str) -> Result<(), String> {
    check_segment("wallet", wallet)?;
    check_segment("id", id)
}

fn note_key(wallet: &str, id: &str) -> String {
    format!("privacy-pools/notes/{wallet}/{id}")
}
fn status_key(wallet: &str, id: &str) -> String {
    format!("privacy-pools/deposits/{wallet}/{id}")
}
fn replacement_key(wallet: &str, id: &str) -> String {
    format!("privacy-pools/replacements/{wallet}/{id}")
}
fn withdrawal_key(wallet: &str, id: &str) -> String {
    format!("privacy-pools/withdrawals/{wallet}/{id}")
}
fn private_relay_key(wallet: &str, id: &str) -> String {
    format!("privacy-pools/private-relays/{wallet}/{id}")
}
fn private_recipient_key(wallet: &str, id: &str) -> String {
    format!("privacy-pools/private-inputs/{wallet}/{id}")
}

/// Store keyed by the user-chosen id (the durable, caller-facing key).
/// Uses `put_new` so a duplicate `<id>` is rejected atomically by the store.
pub fn store_note_by_id(note: &StoredNote, wallet: &str, id: &str) -> Result<(), String> {
    let bytes = serde_json::to_vec(note).map_err(|e| format!("note serialize: {e}"))?;
    sdk::store_put_new(&note_key(wallet, id), &bytes, true).map_err(|e| e.message())
}

/// Overwrite the note keyed by `<wallet>/<id>` in place (no idempotency check).
/// Used to advance a placeholder through `staging` → `staged` / `stage-failed`.
pub fn upsert_note_by_id(note: &StoredNote, wallet: &str, id: &str) -> Result<(), String> {
    let bytes = serde_json::to_vec(note).map_err(|e| format!("note serialize: {e}"))?;
    sdk::store_put(&note_key(wallet, id), &bytes, true).map_err(|e| e.message())
}

/// Read a value from the **secrets** store namespace.
///
/// `petal::sdk::store_get` hardcodes the `state` namespace
/// (`namespace_for_key(_, false)` at every rev we pin), which makes anything
/// written with `secret = true` permanently unreadable through the stock SDK
/// read API. Notes are written with `secret = true` (see `store_note_by_id` /
/// `persist_update`), so the read must target the `secrets` namespace directly
/// via the underlying host binding. The namespace string matches the SDK's own
/// private `SECRET_NS` constant and the on-disk layout under
/// `~/.bloom/petals/data/<hash>/secrets/...`.
fn read_secret(key: &str, max_bytes: usize) -> Result<Option<Vec<u8>>, String> {
    let Some(bytes) = petal::bindings::bloom::store::kv::get("secrets", key)
        .map_err(|e| format!("store get: {e}"))?
    else {
        return Ok(None);
    };
    if bytes.len() > max_bytes {
        return Err(format!(
            "value is {} bytes, exceeds max {max_bytes}",
            bytes.len()
        ));
    }
    Ok(Some(bytes))
}

pub fn load_note(wallet: &str, id: &str) -> Result<Option<StoredNote>, String> {
    match read_secret(&note_key(wallet, id), MAX_NOTE_BYTES)? {
        Some(bytes) => {
            let note: StoredNote =
                serde_json::from_slice(&bytes).map_err(|e| format!("note parse: {e}"))?;
            Ok(Some(note))
        }
        None => Ok(None),
    }
}

pub fn store_status(status: &DepositStatus, wallet: &str, id: &str) -> Result<(), String> {
    let bytes = serde_json::to_vec(status).map_err(|e| format!("status serialize: {e}"))?;
    sdk::store_put(&status_key(wallet, id), &bytes, false).map_err(|e| e.message())
}

/// Update note + status in place after reconciling on-chain state.
pub fn persist_update(note: &StoredNote, wallet: &str, id: &str) -> Result<(), String> {
    let key = note_key(wallet, id);
    let bytes = serde_json::to_vec(note).map_err(|e| format!("note serialize: {e}"))?;
    sdk::store_put(&key, &bytes, true).map_err(|e| e.message())?;
    store_status(&DepositStatus::from(note), wallet, id)
}

/// Public view of a stored note (no secrets), or `None` if not found.
pub fn note_view(wallet: &str, id: &str) -> Result<Option<NoteView>, String> {
    Ok(load_note(wallet, id)?.as_ref().map(NoteView::from))
}

fn listed_suffixes(prefix: &str) -> Result<Vec<String>, String> {
    let mut values = sdk::store_list(prefix, 256 * 1024)
        .map_err(|e| e.message())?
        .into_iter()
        .filter_map(|key| key.strip_prefix(prefix).map(str::to_owned))
        .filter(|suffix| !suffix.is_empty() && !suffix.contains('/'))
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    Ok(values)
}

/// Wallet aliases with at least one public deposit record.
pub fn list_wallets() -> Result<Vec<String>, String> {
    let prefix = "privacy-pools/deposits/";
    let mut wallets = sdk::store_list(prefix, 256 * 1024)
        .map_err(|e| e.message())?
        .into_iter()
        .filter_map(|key| {
            key.strip_prefix(prefix)
                .and_then(|rest| rest.split('/').next())
                .filter(|wallet| !wallet.is_empty())
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    wallets.sort();
    wallets.dedup();
    Ok(wallets)
}

/// Deposit ids for one wallet, derived only from the public state namespace.
pub fn list_ids(wallet: &str) -> Result<Vec<String>, String> {
    validate_idents(wallet, "list")?;
    listed_suffixes(&format!("privacy-pools/deposits/{wallet}/"))
}

pub fn load_replacement(wallet: &str, id: &str) -> Result<Option<ReplacementNote>, String> {
    match read_secret(&replacement_key(wallet, id), MAX_NOTE_BYTES)? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("replacement note parse: {e}")),
        None => Ok(None),
    }
}

pub fn store_withdrawal(status: &WithdrawalStatus) -> Result<(), String> {
    let bytes = serde_json::to_vec(status).map_err(|e| format!("withdrawal serialize: {e}"))?;
    sdk::store_put(
        &withdrawal_key(&status.note_wallet, &status.note_id),
        &bytes,
        false,
    )
    .map_err(|e| e.message())
}

pub fn store_withdrawal_new(status: &WithdrawalStatus) -> Result<(), String> {
    let bytes = serde_json::to_vec(status).map_err(|e| format!("withdrawal serialize: {e}"))?;
    sdk::store_put_new(
        &withdrawal_key(&status.note_wallet, &status.note_id),
        &bytes,
        false,
    )
    .map_err(|e| e.message())
}

pub fn load_withdrawal(wallet: &str, id: &str) -> Result<Option<WithdrawalStatus>, String> {
    match sdk::store_get(&withdrawal_key(wallet, id), MAX_NOTE_BYTES) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("withdrawal parse: {e}")),
        Err(petal::SdkError::Host(petal::HostStatus::NotFound)) => Ok(None),
        Err(e) => Err(e.message()),
    }
}

pub fn store_private_relay(status: &PrivateRelayStatus) -> Result<(), String> {
    let bytes = serde_json::to_vec(status).map_err(|e| format!("private relay serialize: {e}"))?;
    sdk::store_put(
        &private_relay_key(&status.note_wallet, &status.note_id),
        &bytes,
        false,
    )
    .map_err(|e| e.message())
}

pub fn store_private_relay_new(status: &PrivateRelayStatus) -> Result<(), String> {
    let bytes = serde_json::to_vec(status).map_err(|e| format!("private relay serialize: {e}"))?;
    sdk::store_put_new(
        &private_relay_key(&status.note_wallet, &status.note_id),
        &bytes,
        false,
    )
    .map_err(|e| e.message())
}

pub fn load_private_relay(wallet: &str, id: &str) -> Result<Option<PrivateRelayStatus>, String> {
    match sdk::store_get(&private_relay_key(wallet, id), MAX_NOTE_BYTES) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("private relay parse: {e}")),
        Err(petal::SdkError::Host(petal::HostStatus::NotFound)) => Ok(None),
        Err(e) => Err(e.message()),
    }
}

pub fn store_private_recipient(recipient: &PrivateRelayRecipient) -> Result<(), String> {
    let bytes = serde_json::to_vec(recipient)
        .map_err(|e| format!("private relay recipient serialize: {e}"))?;
    let key = private_recipient_key(&recipient.note_wallet, &recipient.note_id);
    if let Some(existing) = read_secret(&key, MAX_NOTE_BYTES)? {
        return if existing == bytes {
            Ok(())
        } else {
            Err("a different private recipient is already stored for this note".into())
        };
    }
    sdk::store_put_new(&key, &bytes, true).map_err(|e| e.message())
}
