petal::route_file!(
    spec: petal::static_read_spec().caps(&["bloom:chain"]),
    read: |_ctx: &petal::Ctx| {
        let pool = crate::protocol::POOL_ETH;
        let size = crate::chain::current_tree_size(pool);
        let asp = crate::chain::latest_asp_root();
        let scope = crate::chain::pool_scope(pool);
        match (size, asp) {
            (Ok(size), Ok(asp)) => petal::read_json_value(&serde_json::json!({
                "pool": format!("{pool:?}"),
                "state_tree_size": size.to_string(),
                "asp_root": format!("0x{asp:x}"),
                "scope": scope.as_ref().map(|s| format!("0x{s:x}")).unwrap_or_default(),
            })),
            (Err(e), _) | (_, Err(e)) => petal::error(-4, format!("could not read pool state: {e}")),
        }
    }
);
