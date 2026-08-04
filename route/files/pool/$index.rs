petal::route_file!(
    spec: petal::static_dir_spec(),
    list: petal::files(&["config.json", "state.json"])
);
