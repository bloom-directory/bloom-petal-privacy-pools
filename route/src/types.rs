//! Wire types for the privacy-pools petal: deposit requests, the private stored
//! note, the public deposit status, the public note view, and the withdrawal
//! proof-input template.
//!
//! Big integers are serialized as decimal strings for amounts/values and as
//! `0x`-prefixed hex for field elements (nullifier/secret/precommitment/
//! commitment/label/roots). This keeps the JSON human-readable and avoids
//! bespoke serde for `U256`.

use serde::{Deserialize, Serialize};

/// Write body for `POST /petals/privacy-pools/deposits/<wallet>/<id>.json`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DepositRequest {
    /// Wei to deposit, as a decimal string (becomes `msg.value`).
    pub amount_wei: String,
    /// Asset to deposit. Only `"eth"` is supported in this release.
    #[serde(default)]
    pub asset: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxRef {
    pub chain: String,
    pub outbox_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
}

/// The complete deposit note. Persisted in the **secrets** store because
/// `nullifier`/`secret` are the only thing that lets the owner withdraw —
/// leaking them is equivalent to losing the funds.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredNote {
    pub wallet: String,
    pub asset: String,
    /// Wei sent (`msg.value`), decimal.
    pub amount_wei: String,
    pub nullifier: String,
    pub secret: String,
    pub precommitment: String,
    pub status: String,
    pub tx: TxRef,
    /// Committed (post-fee) value, decimal. Filled once the `Deposited` log is
    /// reconciled from the receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(default)]
    pub spent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_expires_ms: Option<u64>,
}

/// Public deposit status (state store). Never carries `nullifier`/`secret`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositStatus {
    pub wallet: String,
    pub asset: String,
    /// Wei sent (`msg.value`), decimal.
    pub amount_wei: String,
    pub precommitment: String,
    pub status: String,
    pub tx: TxRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(default)]
    pub spent: bool,
    /// Owner-visible Bloom approval action for the staged deposit, when required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_expires_ms: Option<u64>,
}

impl From<&StoredNote> for DepositStatus {
    fn from(n: &StoredNote) -> Self {
        DepositStatus {
            wallet: n.wallet.clone(),
            asset: n.asset.clone(),
            amount_wei: n.amount_wei.clone(),
            precommitment: n.precommitment.clone(),
            status: n.status.clone(),
            tx: n.tx.clone(),
            value: n.value.clone(),
            label: n.label.clone(),
            commitment: n.commitment.clone(),
            spent: n.spent,
            approval_action_id: n.approval_action_id.clone(),
            approval_expires_ms: n.approval_expires_ms,
        }
    }
}

/// Public note view served at `/petals/privacy-pools/notes/<wallet>/<id>.json`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NoteView {
    pub asset: String,
    pub commitment: Option<String>,
    pub label: Option<String>,
    pub value: Option<String>,
    pub precommitment: String,
    pub status: String,
    pub spent: bool,
}

impl From<&StoredNote> for NoteView {
    fn from(n: &StoredNote) -> Self {
        NoteView {
            asset: n.asset.clone(),
            commitment: n.commitment.clone(),
            label: n.label.clone(),
            value: n.value.clone(),
            precommitment: n.precommitment.clone(),
            status: n.status.clone(),
            spent: n.spent,
        }
    }
}
