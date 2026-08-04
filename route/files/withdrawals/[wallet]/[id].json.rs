petal::route_file!(
    spec: petal::static_read_spec().caps(&["bloom:store", "bloom:chain"]),
    read: |ctx: &petal::Ctx| {
        let wallet = match petal::param(ctx, "wallet") { Ok(v) => v, Err(resp) => return resp };
        let id = match petal::param(ctx, "id") { Ok(v) => v, Err(resp) => return resp };
        crate::withdrawal::prepare(wallet, id)
    }
);
