//! Agent-blind deposit/withdrawal operations.
//!
//! These routes wrap the existing deposit/withdrawal logic but return ONLY
//! sanitized status — no addresses, notes, precommitments, or tx details.
//! The agent delegates here instead of the regular deposit/withdrawal routes,
//! so addresses never enter the agent's (or LLM provider's) context.
//!
//! Future: optionally call a local LLM (Ollama) or Venice for operation
//! reasoning. The LLM I/O stays inside the petal's execution context — the
//! bloom agent never sees it.

use petal::{DispatchResponse, sdk};

pub fn deposit(wallet: &str, id: &str, body: &[u8]) -> DispatchResponse {
    let _ = crate::deposit::create(wallet, id, body);

    let note = match crate::notes::load_note(wallet, id) {
        Ok(Some(n)) => n,
        Ok(None) => {
            return petal::error(-4, "deposit staging did not complete")
        }
        Err(e) => return petal::error(-4, format!("internal error: {e}")),
    };

    if note.status == "stage-failed" {
        return petal::error(
            -4,
            note.label
                .as_deref()
                .unwrap_or("deposit staging failed for an unknown reason"),
        );
    }

    if !note.tx.outbox_id.is_empty()
        && (note.status == "staged" || note.status == "pending")
    {
        let _ = sdk::tx_confirm(wallet, &note.tx.chain, &note.tx.outbox_id, true);
    }

    let status = crate::serde_json::json!({
        "status": "completed",
        "id": id
    });
    let key = format!("state/private/{wallet}/{id}.json");
    let _ = sdk::store_put(&key, &serde_json::to_vec(&status).unwrap_or_default(), false);

    DispatchResponse::Write
}

pub fn read(wallet: &str, id: &str) -> DispatchResponse {
    let key = format!("state/private/{wallet}/{id}.json");
    petal::sdk::store_get(&key, 1024)
        .map(|data| {
            petal::read_json_value(&crate::serde_json::from_slice(&data).unwrap_or_else(|_| {
                crate::serde_json::json!({"status": "not_started"})
            }))
        })
        .unwrap_or_else(|_| {
            petal::read_json_value(&crate::serde_json::json!({"status": "not_started"}))
        })
}
