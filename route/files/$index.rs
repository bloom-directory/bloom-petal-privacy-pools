petal::route_file!(
    spec: petal::static_dir_spec(),
    list: {
        let mut children = petal::files(&["status.json", "protocol.json", "README.md", "AGENTS.md"]);
        children.extend(petal::dir_names(&["pool", "deposits", "notes", "withdrawals"]));
        children
    }
);
