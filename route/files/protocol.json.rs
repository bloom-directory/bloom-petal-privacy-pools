petal::route_file!(
    spec: petal::static_read_spec(),
    read: |_ctx: &petal::Ctx| petal::read_json_value(&serde_json::json!({
        "chain": crate::protocol::CHAIN,
        "entrypoint": format!("{:?}", crate::protocol::ENTRYPOINT),
        "pool_eth": format!("{:?}", crate::protocol::POOL_ETH),
        "native_asset": format!("{:?}", crate::protocol::NATIVE_ASSET),
        "field": {
            "name": "bn254-scalar",
            "p": "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
        },
        "hashing": {
            "node": "poseidon([left,right])",
            "precommitment": "poseidon([nullifier,secret])",
            "commitment": "poseidon([value,label,precommitment])",
            "label": "keccak256(abi.encode(scope,nonce))"
        },
        "sources": [
            "https://docs.privacypools.com/",
            "https://github.com/0xbow-io/privacy-pools-core"
        ]
    }))
);
