fn children(ctx: &petal::Ctx) -> Result<Vec<petal::RouteChild>, petal::DispatchResponse> {
    let wallet = petal::param(ctx, "wallet")?;
    crate::notes::list_ids(wallet)
        .map(|ids| ids.into_iter().map(|id| petal::writable(format!("{id}.json"))).collect())
        .map_err(|e| petal::error(-4, e))
}

petal::route_file!(spec: petal::store_dir_spec().caps(&["bloom:store"]), ctx_list: children);
