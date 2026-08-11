petal::route_file!(
    spec: petal::store_read_spec().caps(&["bloom:store"]),
    read: |ctx: &petal::Ctx| {
        let wallet = match petal::param(ctx, "wallet") {
            Ok(v) => v,
            Err(r) => return r,
        };
        let id = match petal::param(ctx, "id") {
            Ok(v) => v,
            Err(r) => return r,
        };
        match crate::notes::load_note(&wallet, &id) {
            Ok(Some(note)) => {
                let recovery = crate::serde_json::json!({
                    "wallet": note.wallet,
                    "id": id,
                    "nullifier": note.nullifier,
                    "secret": note.secret,
                    "precommitment": note.precommitment,
                    "amount_wei": note.amount_wei,
                    "asset": note.asset,
                    "status": note.status,
                    "spent": note.spent,
                    "warning": "SAVE THIS SECURELY. Without nullifier + secret, the deposit CANNOT be withdrawn. If the petal store is lost (reinstall, corruption), this is the only recovery path."
                });
                petal::read_json_value(&recovery)
            }
            Ok(None) => petal::error(-4, "no such deposit note"),
            Err(e) => petal::error(-4, e),
        }
    }
);
