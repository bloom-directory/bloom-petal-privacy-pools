petal::route_file!(
    spec: petal::store_read_spec(),
    read: |ctx: &petal::Ctx| {
        let wallet = match petal::param(ctx, "wallet") { Ok(v) => v, Err(resp) => return resp };
        let id = match petal::param(ctx, "id") { Ok(v) => v, Err(resp) => return resp };
        match crate::notes::note_view(wallet, id) {
            Ok(Some(view)) => petal::read_json_value(&view),
            Ok(None) => petal::error(-1, "no such note"),
            Err(e) => petal::error(-4, e),
        }
    }
);
