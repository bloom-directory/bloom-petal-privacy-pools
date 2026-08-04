petal::route_file!(
    spec: petal::static_read_spec(),
    read: |_ctx: &petal::Ctx| petal::read_json_value(&serde_json::json!({
        "petal": "privacy-pools",
        "status": "ok",
        "description": "Deposit ETH into the 0xBOW Privacy Pool on Ethereum mainnet. Generates private deposit notes, stages deposits via the tx outbox, reconciles on-chain confirmation, and prepares withdrawal proof inputs. Withdrawal Groth16 proving stays out-of-petal (snarkjs).",
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
            "withdrawal-input-prep",
            "pool-config-read",
            "pool-state-read",
        ],
        "withdrawal_proving": "out-of-petal (snarkjs groth16.fullProve)",
        "docs": ["README.md", "AGENTS.md", "protocol.json"]
    }))
);
