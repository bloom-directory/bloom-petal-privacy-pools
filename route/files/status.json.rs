petal::route_file!(
    spec: petal::static_read_spec(),
    read: |_ctx: &petal::Ctx| petal::read_json_value(&serde_json::json!({
        "petal": "privacy-pools",
        "status": "ok",
        "protocol": "0xBOW Privacy Pools",
        "chain": crate::protocol::CHAIN,
        "canonical_route": "deposits/<wallet>/<id>.json",
        "operations": ["eth-deposit", "deposit-read", "note-view", "withdrawal-input-prep"],
        "withdrawal_proving": "out-of-petal (snarkjs groth16.fullProve)"
    }))
);
