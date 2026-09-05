petal::route_file!(
    spec: petal::write_spec().caps(&[
        "bloom:store",
        "bloom:tx.outbox",
        "bloom:chain",
        "bloom:vfs.read",
    ]),
    read: |ctx: &petal::Ctx| {
        let wallet = match petal::param(ctx, "wallet") { Ok(v) => v, Err(resp) => return resp };
        let id = match petal::param(ctx, "id") { Ok(v) => v, Err(resp) => return resp };
        crate::withdrawal::read(wallet, id)
    },
    write: |ctx: &petal::Ctx, body: &[u8]| {
        let wallet = match petal::param(ctx, "wallet") { Ok(v) => v, Err(resp) => return resp };
        let id = match petal::param(ctx, "id") { Ok(v) => v, Err(resp) => return resp };
        crate::withdrawal::stage(wallet, id, body)
    }
);
