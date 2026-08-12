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
    /// Set only by the local encrypted-backup tool after decrypt-and-compare
    /// verification. Older notes default to false and must be backed up before
    /// a withdrawal may be staged.
    #[serde(default)]
    pub backup_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_ceremony_url: Option<String>,
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
    #[serde(default)]
    pub backup_verified: bool,
    /// Owner-approval ceremony for the staged deposit, when Bloom requires one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_ceremony_url: Option<String>,
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
            backup_verified: n.backup_verified,
            approval_action_id: n.approval_action_id.clone(),
            approval_ceremony_url: n.approval_ceremony_url.clone(),
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
    pub backup_verified: bool,
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
            backup_verified: n.backup_verified,
        }
    }
}

/// Private replacement commitment prepared by the companion prover. This is
/// written directly to the active petal secrets store and never crosses a VFS
/// read or write body.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplacementNote {
    pub parent_wallet: String,
    pub parent_id: String,
    pub replacement_id: String,
    pub remaining_value: String,
    pub label: String,
    pub new_commitment: String,
    pub nullifier: String,
    pub secret: String,
    pub calldata_hash: String,
    #[serde(default)]
    pub backup_verified: bool,
}

/// Public request accepted by a direct-withdrawal route. The proof itself is
/// carried in calldata; all secret-dependent values are independently checked
/// against the private note and replacement record.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawalRequest {
    pub signing_wallet: String,
    pub replacement_id: String,
    pub calldata: String,
}

/// Agent-visible request to begin a relayed withdrawal without supplying the
/// recipient. Bloom collects the destination in a passkey-bound local
/// ceremony and releases it only to this petal and its trusted companion.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateRelayRequest {
    pub mode: String,
    pub replacement_id: String,
    /// Optional passkey wallet used only to approve the private destination.
    /// This need not be the wallet that owns the deposited note.
    #[serde(default)]
    pub approval_wallet: Option<String>,
    #[serde(default)]
    pub amount_wei: Option<String>,
}

/// Public lifecycle state. It deliberately contains no recipient, calldata,
/// proof, relayer payload, or transaction hash.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateRelayStatus {
    pub note_wallet: String,
    pub note_id: String,
    pub replacement_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_wallet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_wei: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ceremony_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ceremony_expires_ms: Option<u64>,
    pub next: String,
}

/// Secret hand-off record read by the local prover/relayer companion.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateRelayRecipient {
    pub schema: String,
    pub note_wallet: String,
    pub note_id: String,
    pub replacement_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_wei: Option<String>,
    pub recipient: String,
}

/// Public, durable withdrawal lifecycle record.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawalStatus {
    pub note_wallet: String,
    pub note_id: String,
    pub signing_wallet: String,
    pub processooor: String,
    pub withdrawal_value_wei: String,
    pub existing_nullifier_hash: String,
    pub new_commitment: String,
    pub state_root: String,
    pub asp_root: String,
    pub replacement_id: String,
    pub calldata_hash: String,
    pub status: String,
    pub tx: TxRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_ceremony_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_expires_ms: Option<u64>,
    #[serde(default)]
    pub settlement_verified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_relay_public_status_cannot_serialize_a_recipient() {
        let status = PrivateRelayStatus {
            note_wallet: "dev".into(),
            note_id: "note-1".into(),
            replacement_id: "note-2".into(),
            approval_wallet: Some("owner-passkey".into()),
            amount_wei: None,
            status: "destination-ready".into(),
            ceremony_url: None,
            ceremony_expires_ms: None,
            next: "run the local relay helper".into(),
        };
        let encoded = serde_json::to_value(status).unwrap();
        assert!(encoded.get("recipient").is_none());
        assert!(encoded.get("calldata").is_none());
        assert!(encoded.get("proof").is_none());
        assert!(encoded.get("tx_hash").is_none());
    }
}
