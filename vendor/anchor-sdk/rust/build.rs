use std::{fs, path::PathBuf};

fn main() {
    let protocol_root = PathBuf::from("../protocol");
    let proto_root = protocol_root.join("anchor/v1");
    let mut protos = fs::read_dir(&proto_root)
        .expect("protocol source directory must exist")
        .map(|entry| entry.expect("protocol directory entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "proto")
        })
        .collect::<Vec<_>>();
    protos.extend(
        fs::read_dir(proto_root.join("capabilities"))
            .expect("capability protocol source directory must exist")
            .map(|entry| entry.expect("capability protocol directory entry").path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "proto")
            }),
    );
    protos.sort();

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    let mut config = prost_build::Config::new();
    config.include_file("wire.rs");
    config
        .compile_protos(&protos, &[protocol_root])
        .expect("Anchor protocol schemas must compile");
}
