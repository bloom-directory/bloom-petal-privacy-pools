petal::route_file!(
    spec: petal::static_read_spec().caps(&["bloom:chain"]),
    read: |_ctx: &petal::Ctx| {
        match crate::chain::asset_config(crate::protocol::NATIVE_ASSET) {
            Ok((pool, min, vet, max_relay)) => petal::read_json_value(&serde_json::json!({
                "asset": "eth",
                "pool": format!("{pool:?}"),
                "minimum_deposit_wei": min.to_string(),
                "vetting_fee_bps": vet.to_string(),
                "max_relay_fee_bps": max_relay.to_string(),
            })),
            Err(e) => petal::error(-4, format!("could not read pool config: {e}")),
        }
    }
);
