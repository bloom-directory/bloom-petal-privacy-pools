//! Private note + public status persistence through Bloom's `bloom:store`.
//!
//! Notes (with `nullifier`/`secret`) live in the **secrets** namespace; public
//! deposit status lives in the **state** namespace. Keys are namespaced under
//! `privacy-pools/...` so they never collide with another petal.

use petal::sdk;

use crate::types::{DepositStatus, NoteView, StoredNote};

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

pub fn load_note(wallet: &str, id: &str) -> Result<Option<StoredNote>, String> {
    match sdk::store_get(&note_key(wallet, id), MAX_NOTE_BYTES) {
        Ok(bytes) => {
            let note: StoredNote =
                serde_json::from_slice(&bytes).map_err(|e| format!("note parse: {e}"))?;
            Ok(Some(note))
        }
        Err(petal::SdkError::Host(petal::HostStatus::NotFound)) => Ok(None),
        Err(e) => Err(e.message()),
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
