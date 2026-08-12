petal::route_file!(
    spec: petal::store_dir_spec().caps(&["bloom:store"]),
    fallible_list: crate::notes::list_wallets()
        .map(petal::dirs)
        .map_err(|e| petal::error(-4, e)),
);
