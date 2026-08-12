petal::route_file!(
    spec: petal::static_read_spec(),
    read: |_ctx: &petal::Ctx| petal::read_json_value(&serde_json::json!({
        "petal": "privacy-pools",
        "status": "ok",
        "description": "Deposit ETH into the 0xBOW Privacy Pool on Ethereum mainnet. Direct withdrawals use Bloom owner approval; recipient-private withdrawals use a passkey-bound local ceremony and protocol relayer without exposing the destination through VFS.",
        "protocol": {
            "name": "0xBOW Privacy Pools",
            "chain": crate::protocol::CHAIN,
            "entrypoint": format!("{:?}", crate::protocol::ENTRYPOINT),
            "pool_eth": format!("{:?}", crate::protocol::POOL_ETH),
            "docs": "https://docs.privacypools.com/",
        },
        "supported_assets": [
            {
                "asset": "eth",
                "symbol": "ETH",
                "decimals": 18,
            }
        ],
        "canonical_route": "deposits/<wallet>/<id>.json",
        "operations": [
            "eth-deposit",
            "deposit-read-and-reconcile",
            "note-view",
            "withdrawal-readiness-preview",
            "encrypted-note-backup-and-restore-tool",
            "official-sdk-withdrawal-prover-tool",
            "direct-withdrawal-validate-simulate-stage",
            "recipient-private-relayed-withdrawal",
            "withdrawal-event-reconciliation",
            "onchain-spent-nullifier-reconciliation",
            "deposit-and-note-directory-listing",
            "pool-config-read",
            "pool-state-read",
        ],
        "withdrawal_proving": "out-of-petal; use the official @0xbow/privacy-pools-core-sdk locally",
        "withdrawal_submission": "direct withdrawals use the Bloom outbox; recipient-private withdrawals use Entrypoint.relay through the redacting local companion",
        "spent_status": "reconciled from PrivacyPool.nullifierHashes(poseidon(nullifier)) without exposing note secrets",
        "backup_policy": "direct withdrawal staging requires verified encrypted backups for the existing and replacement notes",
        "docs": ["README.md", "AGENTS.md", "WITHDRAWAL.md", "protocol.json"]
    }))
);
